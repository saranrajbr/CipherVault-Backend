"""Vercel serverless entrypoint.

Vercel discovers Python entrypoints in the ``api`` directory and exposes each
file as a function named after its route. ``api/index.py`` therefore becomes
the ``/api`` function, and ``vercel.json`` rewrites every request to it so the
FastAPI router sees the original path and can serve ``/api/*``, ``/docs`` and
``/openapi.json`` itself.

The import below mirrors how the app is started locally, with the repository
root placed on ``sys.path`` first because a Vercel function runs with its own
directory as the working directory.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.main import app  # noqa: E402  (path setup must run first)

__all__ = ["app"]