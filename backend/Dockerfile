FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY --from=ghcr.io/astral-sh/uv:0.8 /uv /uvx /bin/
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY athar ./athar
RUN uv sync --frozen --no-dev && useradd -r -u 10001 athar && mkdir -p /app/data && chown -R athar:athar /app
USER athar
ENV PATH="/app/.venv/bin:$PATH"
EXPOSE 8000
CMD ["athar", "serve"]
