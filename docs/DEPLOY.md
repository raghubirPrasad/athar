# Deploying the hosted instance

The judges get a URL and a viewer account. Compute stays on our machine; Cloudflare Tunnel
exposes the `public` compose profile. Nothing here is needed for the local judge path
(`make demo`).

## 1. Prepare `.env`

```
cp .env.example .env
```

Then change, at minimum:

| Variable | Value |
|---|---|
| `ATHAR_DEV` | `false` (refuses the example JWT secret) |
| `JWT_SECRET` | `openssl rand -hex 32` |
| `DEMO_ANALYST_PASSWORD`, `DEMO_APPROVER_PASSWORD`, `DEMO_JUDGE_PASSWORD` | long random values; the judge one goes into the submission PDF |
| `COOKIE_SECURE` | `true` |
| `PUBLIC_URL` | `https://<hostname>` (CORS is restricted to it) |
| `PUBLIC_HOSTNAME` | `<hostname>` (Caddy vhost) |
| `LLM_PROVIDER` / `LLM_MODEL` / `GEMINI_API_KEY` | `gemini`, the model id available on the free tier, and the key |

## 2. Bring it up

```
docker compose --profile public up -d --build --wait
make seed
make agent      # warms the LLM cache so the demo never waits on the network
```

`make seed` is idempotent; run it again after any restart to confirm "already anchored".

`PUBLIC_HOSTNAME` reaches Caddy through the `caddy` service's `environment:` block, so the value
you put in `.env` is the vhost Caddy answers on. Leave it unset and Caddy serves `localhost` with
a self-signed certificate, which is the right default locally and useless in front of a tunnel.

## 3. Tunnel

```
cloudflared tunnel login
cloudflared tunnel create athar
cloudflared tunnel route dns athar <hostname>
cloudflared tunnel run --url http://localhost:80 athar
```

Caddy terminates TLS on the public profile; if the tunnel terminates TLS instead, point it
at `http://localhost:8080` (the `web` container) and set `COOKIE_SECURE=true` anyway, since
the browser still sees HTTPS.

## Optional: the local LLM profile

The hosted instance runs `LLM_PROVIDER=gemini` with a warm cache (SPEC §18.5); the `local-llm`
profile is for development and the offline fallback. The `ollama` image ships with **no models**,
so the one SPEC §18.1 names has to be pulled once, by hand, after the service is up:

```
docker compose --profile local-llm up -d ollama
docker compose --profile local-llm exec ollama ollama pull qwen3:8b   # ~5 GB, once; cached in the `ollama` volume
```

It is deliberately not a step inside `up`: the download takes minutes, would block
`up --wait`, and would fail the whole profile on a flaky network. Until it has run, `/api/chat`
answers 404, the client marks the provider fatal and the agent layer falls back to templates
(SPEC §11.2) — degraded, never broken. Then set `LLM_PROVIDER=ollama` and `OLLAMA_URL` (compose
already points it at `http://ollama:11434`).

## 4. Rehearsal checklist

- [ ] `make demo` twice on a laptop that has never seen the repo: second run prints twelve
      "already anchored" lines, one per month, and no duplicates. The last reads
      `month 12: 99 findings · root 0xc1559c8d30ae… · already anchored`.
- [ ] `make eval` after the re-seed: the Evaluation page reads `data/eval/results-7.json` from disk
      and will otherwise show the previous estate's precision and recall.
- [ ] Log in as `judge@athar.local`: every page renders, no mutating button is enabled.
- [ ] Log in as `approver@athar.local`: propose → approve → apply on one finding; the score drops.
- [ ] `make verify` passes; `athar tamper --finding <key>` then `make verify` fails; the badge is red
      on the next page load, without pressing Verify.
- [ ] Network off (except the local Anvil): every demo beat still works from the LLM cache.
