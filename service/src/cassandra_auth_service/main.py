"""Entrypoint for the auth service."""

from __future__ import annotations

import logging
import os

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")


def cli() -> None:
    import uvicorn  # noqa: PLC0415

    from cassandra_auth_service.app import create_app  # noqa: PLC0415

    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))

    app = create_app()
    uvicorn.run(app, host=host, port=port)
