"""LLM client with provider fallback, cache and output guard (SPEC §11.2).

Providers: `gemini` (google-genai), `ollama` (HTTP `/api/chat`, `format: json`),
`none` (raise `TemplateFallback` so the caller renders its template). Order:
`LLM_PROVIDER` first, then the chain gemini → ollama → none. Every provider
call: `LLM_TIMEOUT_SECONDS` timeout, two retries with a small backoff, at most
`LLM_MAX_CONCURRENCY` in flight. Every response is validated by the pydantic
schema and then by `guard.validate_output`; only the validated output is cached.

The transports are injectable (`transports=`) so tests never touch the network.
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from athar.agents import guard
from athar.agents.cache import CacheEntry, CacheStore, cache_key, input_hash
from athar.agents.schemas import GeneratedBy
from athar.config import Settings, get_settings
from athar.log import get_logger

log = get_logger(__name__)

PROVIDER_CHAIN: tuple[str, ...] = ("gemini", "ollama", "none")
MAX_RETRIES = 2
TEMPLATE_MODEL_ID = "template"

_M = TypeVar("_M", bound=BaseModel)
_FENCE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)


class TemplateFallback(Exception):  # noqa: N818 — name is the SPEC §11.2 contract
    """Raised when no provider produced a valid output; the caller uses its template."""

    def __init__(self, reasons: Sequence[str]) -> None:
        super().__init__("; ".join(reasons) or "no LLM provider available")
        self.reasons = list(reasons)


class ProviderError(Exception):
    """Any provider failure (auth, quota, timeout, transport, unparsable JSON).

    `fatal` marks a failure that will not fix itself on the next call — an invalid key, a model
    this key cannot reach. Retrying it wastes the caller's time on every finding, so the client
    stops offering that provider for the rest of the process and goes straight to the next one.
    """

    def __init__(self, detail: str, *, fatal: bool = False) -> None:
        super().__init__(detail)
        self.fatal = fatal


_FATAL_MARKERS: tuple[str, ...] = (
    "api_key_invalid",
    "api key not valid",
    "permission_denied",
    "unauthenticated",
    "invalid authentication",
    "model not found",
    "does not exist",
)


def is_fatal_provider_message(text: str) -> bool:
    """A provider message that means "this configuration will never work", not "try again"."""
    lowered = text.lower()
    return any(marker in lowered for marker in _FATAL_MARKERS)


@dataclass(frozen=True)
class ProviderRequest:
    provider: str
    model: str
    system: str
    user_payload: dict[str, Any]
    schema: type[BaseModel]
    timeout_seconds: float


Transport = Callable[[ProviderRequest], str]
"""Sends one request and returns the raw model text (expected to contain one JSON object)."""


@dataclass(frozen=True)
class LlmResult:
    output: BaseModel
    provider: str
    model_id: str
    prompt_version: str
    cached: bool
    generated_by: GeneratedBy
    guard_flags: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# JSON extraction
# ---------------------------------------------------------------------------


def extract_json_object(text: str) -> dict[str, Any]:
    """Parse the first JSON object in `text`, tolerating ``` fences and leading prose."""
    if not text or not text.strip():
        raise ProviderError("empty response")
    stripped = _FENCE.sub("", text.strip())
    try:
        obj = json.loads(stripped)
    except json.JSONDecodeError:
        start, end = stripped.find("{"), stripped.rfind("}")
        if start < 0 or end <= start:
            raise ProviderError("no JSON object in response") from None
        try:
            obj = json.loads(stripped[start : end + 1])
        except json.JSONDecodeError as exc:
            raise ProviderError(f"invalid JSON: {exc.msg}") from None
    if not isinstance(obj, dict):
        raise ProviderError("response is not a JSON object")
    return obj


# ---------------------------------------------------------------------------
# Transports
# ---------------------------------------------------------------------------


_SCHEMA_REJECTION_HINTS: tuple[str, ...] = ("schema", "properties", "invalid_argument", "400")


def _looks_like_schema_rejection(exc: Exception) -> bool:
    """True when the API refused our response_schema (e.g. an open `dict` field) rather than the request."""
    text = f"{exc.__class__.__name__} {exc}".lower()
    return any(hint in text for hint in _SCHEMA_REJECTION_HINTS)


def gemini_transport(req: ProviderRequest) -> str:
    """google-genai call with JSON mime type and the pydantic schema as `response_schema`.

    Gemini rejects object schemas without declared properties (`PlanOutput.params` is an
    open dict), so when the API refuses the schema we retry once with JSON mime type only
    and let `extract_json_object` + pydantic do the validation (SPEC §11.2).
    """
    settings = get_settings()
    api_key = settings.effective_gemini_key
    if not api_key:
        raise ProviderError("gemini: no API key configured", fatal=True)
    try:
        from google import genai
        from google.genai import types
    except ImportError as exc:  # pragma: no cover — declared dependency
        raise ProviderError(f"gemini: sdk unavailable ({exc.__class__.__name__})") from None

    contents = json.dumps(req.user_payload, ensure_ascii=False)

    def _call(with_schema: bool) -> Any:
        client = genai.Client(
            api_key=api_key,
            http_options=types.HttpOptions(timeout=int(req.timeout_seconds * 1000)),
        )
        config = types.GenerateContentConfig(
            system_instruction=req.system,
            response_mime_type="application/json",
            response_schema=req.schema if with_schema else None,
            temperature=0.0,
        )
        return client.models.generate_content(model=req.model, contents=contents, config=config)

    try:
        try:
            resp = _call(with_schema=True)
        except Exception as exc:
            if not _looks_like_schema_rejection(exc):
                raise
            log.info("gemini rejected response_schema; retrying with JSON mime type only")
            resp = _call(with_schema=False)
    except Exception as exc:  # every SDK failure class collapses to a provider error
        raise ProviderError(
            f"gemini: {exc.__class__.__name__}", fatal=is_fatal_provider_message(str(exc))
        ) from None
    text = getattr(resp, "text", None)
    if not text:
        raise ProviderError("gemini: empty response")
    return str(text)


def ollama_transport(req: ProviderRequest) -> str:
    """POST {OLLAMA_URL}/api/chat with `format: "json"` and streaming disabled."""
    settings = get_settings()
    url = settings.ollama_url.rstrip("/") + "/api/chat"
    body = {
        "model": req.model,
        "format": "json",
        "stream": False,
        "think": False,
        "options": {"temperature": 0},
        "messages": [
            {"role": "system", "content": req.system},
            {"role": "user", "content": json.dumps(req.user_payload, ensure_ascii=False)},
        ],
    }
    try:
        resp = httpx.post(url, json=body, timeout=req.timeout_seconds)
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPStatusError as exc:
        # 404 from /api/chat means this model is not pulled: no amount of retrying fixes it.
        fatal = exc.response.status_code == 404 or is_fatal_provider_message(exc.response.text)
        raise ProviderError(f"ollama: {exc.__class__.__name__}", fatal=fatal) from None
    except httpx.HTTPError as exc:
        raise ProviderError(f"ollama: {exc.__class__.__name__}") from None
    except ValueError:
        raise ProviderError("ollama: non-JSON body") from None
    content = data.get("message", {}).get("content") if isinstance(data, dict) else None
    if not content:
        raise ProviderError("ollama: empty response")
    return str(content)


DEFAULT_TRANSPORTS: dict[str, Transport] = {"gemini": gemini_transport, "ollama": ollama_transport}


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


def provider_chain(primary: str) -> list[str]:
    """`LLM_PROVIDER` first, then gemini → ollama → none. `none` means templates only."""
    if primary == "none":
        return ["none"]
    return [primary] + [p for p in PROVIDER_CHAIN if p != primary]


class LlmClient:
    def __init__(
        self,
        settings: Settings | None = None,
        *,
        transports: Mapping[str, Transport] | None = None,
        backoff_seconds: float = 0.25,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._settings = settings or get_settings()
        self._transports: dict[str, Transport] = dict(
            transports if transports is not None else DEFAULT_TRANSPORTS
        )
        self._backoff = backoff_seconds
        self._sleep = sleep
        self._semaphore = threading.Semaphore(max(1, self._settings.llm_max_concurrency))
        self._disabled: dict[str, str] = {}  # provider -> why, after a fatal configuration failure

    # -- public -----------------------------------------------------------------
    def model_for(self, provider: str) -> str:
        if provider == "gemini":
            return self._settings.llm_model
        if provider == "ollama":
            return self._settings.ollama_model
        return TEMPLATE_MODEL_ID

    def chain(self) -> list[str]:
        return provider_chain(self._settings.llm_provider)

    def generate(
        self,
        schema: type[_M],
        *,
        system: str,
        user_payload: dict[str, Any],
        prompt_version: str,
        cache: CacheStore | None,
        regenerate: bool = False,
        allowed_actions: Sequence[str] | None = None,
    ) -> LlmResult:
        """Structured generation with cache, provider fallback and output guard.

        Raises `TemplateFallback` when every provider fails or the chain is `none`.
        `allowed_actions` defaults to `user_payload["allowed_actions"]`.
        """
        actions = list(
            allowed_actions if allowed_actions is not None else user_payload.get("allowed_actions", [])
        )
        payload_hash = input_hash(user_payload)
        chain = self.chain()

        if cache is not None and not regenerate:
            hit = self._lookup(cache, chain, prompt_version, payload_hash, schema, actions, user_payload)
            if hit is not None:
                return hit

        reasons: list[str] = []
        for provider in chain:
            if provider == "none":
                reasons.append("none: templates only")
                break
            transport = self._transports.get(provider)
            if transport is None:
                reasons.append(f"{provider}: no transport")
                continue
            model = self.model_for(provider)
            req = ProviderRequest(
                provider=provider,
                model=model,
                system=system,
                user_payload=user_payload,
                schema=schema,
                timeout_seconds=float(self._settings.llm_timeout_seconds),
            )
            if provider in self._disabled:
                reasons.append(f"{provider}: disabled ({self._disabled[provider]})")
                continue
            try:
                validated, flags = self._call_with_retries(transport, req, actions)
            except ProviderError as exc:
                reasons.append(str(exc))
                if getattr(exc, "fatal", False):
                    self._disabled[provider] = str(exc)
                    log.warning(
                        "llm provider disabled for this process",
                        extra={"provider": provider, "reason": str(exc)},
                    )
                else:
                    log.warning(
                        "llm provider failed, falling back",
                        extra={"provider": provider, "reason": str(exc)},
                    )
                continue
            if cache is not None:
                cache.put(
                    cache_key(prompt_version, model, payload_hash),
                    CacheEntry(
                        provider=provider,
                        model=model,
                        prompt_version=prompt_version,
                        input_hash=payload_hash,
                        output=validated.model_dump(mode="json"),
                    ),
                )
            return LlmResult(
                output=validated,
                provider=provider,
                model_id=model,
                prompt_version=prompt_version,
                cached=False,
                generated_by="model",
                guard_flags=tuple(flags),
            )
        raise TemplateFallback(reasons)

    # -- internals --------------------------------------------------------------
    def _lookup(
        self,
        cache: CacheStore,
        chain: list[str],
        prompt_version: str,
        payload_hash: str,
        schema: type[_M],
        actions: list[str],
        user_payload: dict[str, Any],
    ) -> LlmResult | None:
        for provider in chain:
            if provider == "none":
                continue
            model = self.model_for(provider)
            entry = cache.get(cache_key(prompt_version, model, payload_hash))
            if entry is None:
                continue
            try:
                parsed = schema.model_validate(entry.output)
            except ValidationError:
                log.warning("llm cache entry does not match schema; ignoring", extra={"provider": provider})
                continue
            flags: list[str] = []
            # Defence in depth: the guard re-runs on cached output too.
            validated = guard.validate_output(
                parsed, allowed_actions=actions, input_payload=user_payload, flags=flags
            )
            return LlmResult(
                output=validated,
                provider=entry.provider,
                model_id=entry.model,
                prompt_version=entry.prompt_version,
                cached=True,
                generated_by="model",
                guard_flags=tuple(flags),
            )
        return None

    def _call_with_retries(
        self, transport: Transport, req: ProviderRequest, actions: list[str]
    ) -> tuple[Any, list[str]]:
        last: ProviderError | None = None
        for attempt in range(MAX_RETRIES + 1):
            if attempt:
                self._sleep(self._backoff * attempt)
            try:
                return self._call_once(transport, req, actions)
            except ProviderError as exc:
                last = exc
                log.info(
                    "llm attempt failed",
                    extra={"provider": req.provider, "attempt": attempt, "reason": str(exc)},
                )
                if exc.fatal:
                    break
        raise last if last is not None else ProviderError(f"{req.provider}: unknown failure")

    def _call_once(
        self, transport: Transport, req: ProviderRequest, actions: list[str]
    ) -> tuple[Any, list[str]]:
        with self._semaphore:
            try:
                text = transport(req)
            except ProviderError:
                raise
            except (httpx.HTTPError, TimeoutError, OSError, ValueError) as exc:
                raise ProviderError(f"{req.provider}: {exc.__class__.__name__}") from None
            except Exception as exc:  # a provider must never crash the caller
                raise ProviderError(f"{req.provider}: {exc.__class__.__name__}") from None
        obj = extract_json_object(text)
        try:
            parsed = req.schema.model_validate(obj)
        except ValidationError as exc:
            raise ProviderError(
                f"{req.provider}: schema validation failed ({exc.error_count()} errors)"
            ) from None
        flags: list[str] = []
        validated = guard.validate_output(
            parsed, allowed_actions=actions, input_payload=req.user_payload, flags=flags
        )
        return validated, flags
