"""Pytest fixtures for the SecWeb backend test-suite.

Each test gets a hermetic environment:

* a fresh in-memory-ish SQLite file under ``tmp_path``
* a fresh ``fakeredis`` (real TTL semantics)
* a temp-dir encrypted store
* one registered user + one second user (cross-tenant)

``bcrypt`` is slow, so user registration happens once per test (not per
request) — the fixtures below pre-register and hand the test a ready JWT.
"""
from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

# Make `app` importable regardless of how pytest is invoked.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.config import configure, reset_configure  # noqa: E402
from app.core.cache import make_cache  # noqa: E402
from app.core.storage import Store  # noqa: E402
from app.models.repo import Repository  # noqa: E402
from app.models.schema import Database  # noqa: E402
from app.main import create_app  # noqa: E402


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


USER1 = {"username": "alice", "password": "pw-alice", "key1": b"K1-alice-0123456789", "key2": b"K2-alice-0123456789"}
USER2 = {"username": "bob", "password": "pw-bob", "key1": b"K1-bob-0123456789", "key2": b"K2-bob-0123456789"}


@pytest.fixture()
def env(tmp_path: Path):
    """A fully wired app + repo + cache + store in a temp dir."""
    reset_configure()
    configure(
        SECWEB_JWT_SECRET="test-secret-0123456789",
        SECWEB_STORAGE_DIR=str(tmp_path / "storage"),
        SECWEB_DB_PATH=str(tmp_path / "db.sqlite"),
        SECWEB_REDIS_URL="redis://fake/0",
        SECWEB_DEFAULT_TTL_SECONDS="60",
    )
    db = Database(str(tmp_path / "db.sqlite"))
    store = Store(str(tmp_path / "storage"))
    import fakeredis

    cache = make_cache(fakeredis.FakeRedis(decode_responses=False))
    repo = Repository(db)
    app = create_app(db=db, cache=cache, store=store, repo=repo)

    class Env:
        pass

    e = Env()
    e.app = app
    e.db = db
    e.store = store
    e.cache = cache
    e.repo = repo
    e.tmp = tmp_path
    yield e
    db.close()
    reset_configure()


@pytest.fixture()
def client(env):
    from fastapi.testclient import TestClient

    with TestClient(env.app, raise_server_exceptions=True) as c:
        yield c


def _register_user(repo: Repository, spec: dict) -> int:
    return repo.register(spec["username"], spec["password"], spec["key1"], spec["key2"]).id


@pytest.fixture()
def user1_id(env) -> int:
    return _register_user(env.repo, USER1)


@pytest.fixture()
def user2_id(env) -> int:
    return _register_user(env.repo, USER2)


@pytest.fixture()
def jwt1(env, user1_id) -> str:
    from app.core import auth as authcore

    return authcore.create_jwt(user1_id, USER1["username"])


@pytest.fixture()
def jwt2(env, user2_id) -> str:
    from app.core import auth as authcore

    return authcore.create_jwt(user2_id, USER2["username"])


@pytest.fixture()
def headers1(env, jwt1) -> dict:
    return {
        "Authorization": f"Bearer {jwt1}",
        "X-Sec-Key-1": _b64(USER1["key1"]),
        "X-Sec-Key-2": _b64(USER1["key2"]),
    }


@pytest.fixture()
def headers2(env, jwt2) -> dict:
    return {
        "Authorization": f"Bearer {jwt2}",
        "X-Sec-Key-1": _b64(USER2["key1"]),
        "X-Sec-Key-2": _b64(USER2["key2"]),
    }
