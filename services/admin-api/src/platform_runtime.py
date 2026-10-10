"""Briareus Admin health shell; owner-signed BFF is not publicly activated.

No cross-owner SQLAlchemy session or old global schema readiness is allowed.
The real BFF must use independently verified Identity/Access/Control/Catalog
source-owner API ports after reviewer acceptance of C1-B2/C2.
"""

from __future__ import annotations

from fastapi import FastAPI


def create_platform_admin_app(services: object | None = None) -> FastAPI:
    if services is not None:
        raise RuntimeError("global PlatformServices BFF rejected: owner service ports required")
    app = FastAPI(
        title="Briareus Administration",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/health/live", include_in_schema=False)
    async def live() -> dict[str, str]:
        return {"state": "live", "api": "unmounted", "authorization": "not_attested"}

    return app


app = create_platform_admin_app()
