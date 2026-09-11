"""SecWeb FastAPI application (SPEC.md §1 + binding API contract).

Wires together:

* the crypto core (:mod:`app.core`),
* the SQLite repository (:mod:`app.models`),
* the ephemeral TTL cache (:mod:`app.core.cache`),
* the encrypted file store (:mod:`app.core.storage`),
* and the API routers (:mod:`app.api`).

``create_app`` accepts optional overrides so the test-suite can inject a
temp-dir store / fakeredis / temp SQLite without touching the environment.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI

from app import __version__
from app.api import auth_routes, favorites_routes, file_routes, folder_routes
from app.config import Settings, get_settings
from app.core.cache import TTLCache, make_cache
from app.core.storage import Store
from app.models.repo import Repository
from app.models.schema import Database


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ``app.state`` is populated either by the injected overrides (tests) or,
    # if absent, by the production builders below.
    if not hasattr(app.state, "repo"):
        s: Settings = get_settings()
        db = Database(s.db_path)
        app.state.db = db
        app.state.store = Store(s.storage_dir)
        app.state.cache = make_cache()
        app.state.repo = Repository(db)
    try:
        yield
    finally:
        db = getattr(app.state, "db", None)
        if db is not None:
            db.close()


def create_app(
    settings: Optional[Settings] = None,
    *,
    db: Optional[Database] = None,
    cache: Optional[TTLCache] = None,
    store: Optional[Store] = None,
    repo: Optional[Repository] = None,
) -> FastAPI:
    """Application factory.

    Production: call with no arguments — settings come from the environment.
    Tests: pass explicit ``db`` / ``cache`` / ``store`` / ``repo``.
    """
    app = FastAPI(
        title="SecWeb",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
    )

    # Injected instances win over environment-driven ones.
    if db is not None:
        app.state.db = db
    if store is not None:
        app.state.store = store
    if cache is not None:
        app.state.cache = cache
    if repo is not None:
        app.state.repo = repo

    # If a repo was not injected but a db was, build one on top of it.
    if repo is None and db is not None:
        app.state.repo = Repository(db)

    app.include_router(auth_routes.router)
    app.include_router(folder_routes.router)
    app.include_router(file_routes.router)
    app.include_router(favorites_routes.router)

    @app.get("/api/health", tags=["meta"])
    def health() -> dict:
        version = getattr(settings, "version", __version__) if settings else __version__
        cache_obj = getattr(app.state, "cache", None)
        try:
            redis_state = "up" if (cache_obj is not None and cache_obj.ping()) else "down"
        except Exception:
            redis_state = "down"
        return {"status": "ok", "version": version, "redis": redis_state}

    return app


# Convenience module-level app for ``uvicorn app.main:app``.
app = create_app()
