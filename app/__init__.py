"""SecWeb backend — zero-knowledge, multi-user encrypted media portal.

Package layout (mirrors the binding spec in ``docs/SPEC.md``):

    app/
      core/      # security, encryption, cache, storage
      api/       # FastAPI routes
      models/    # SQLite schema + repository
      main.py    # FastAPI application entrypoint
"""

__version__ = "1.0.0"
