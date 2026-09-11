"""Start uvicorn on `API_HOST:API_PORT` (called by `athar serve`).

`app` is either an import string (`module:factory`, served with `factory=True`, reload-capable)
or a ready FastAPI instance. The integrator passes its own zero-argument factory — one that
calls `athar.api.app.create_app(startup_hooks=[...])` and installs `app.state.repo_factory` —
so the served process is wired to the real services.
"""

from __future__ import annotations

import uvicorn
from fastapi import FastAPI

from athar.config import Settings, get_settings
from athar.log import configure

DEFAULT_APP = "athar.api.app:create_app"


def run(settings: Settings | None = None, *, app: str | FastAPI = DEFAULT_APP, reload: bool = False) -> None:
    s = settings or get_settings()
    s.assert_startable()
    configure(s.log_level)
    if reload and not isinstance(app, str):
        raise ValueError("reload needs an import string, not an app instance")
    uvicorn.run(
        app,
        factory=isinstance(app, str),
        host=s.api_host,
        port=s.api_port,
        reload=reload,
        log_level=s.log_level.lower(),
        # Only a proxy declared in TRUSTED_PROXY_CIDRS may rewrite the client address; with the
        # empty default uvicorn leaves `scope["client"]` alone, which is what
        # `security.limits.client_ip` keys the rate limiter on (SPEC §15.3).
        proxy_headers=bool(s.trusted_proxy_cidrs),
        forwarded_allow_ips=list(s.trusted_proxy_cidrs),
        server_header=False,
        date_header=True,
    )
