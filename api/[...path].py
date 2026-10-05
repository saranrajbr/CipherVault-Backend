"""Vercel serverless entrypoint.

The filename ``[...path].py`` makes this a catch-all function, so Vercel routes
every ``/api/*`` request here while preserving the original path. FastAPI
therefore sees ``/api/health``, ``/api/algorithms`` and so on and can match its
own routes. A plain ``index.py`` would only receive ``/api`` and 404 on
everything else.

The repository root is placed on ``sys.path`` first because a Vercel function
runs with its own directory as the working directory.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.main import app  # noqa: E402  (path setup must run first)

__all__ = ["app"]