"""Ensure the downloaded competition SDK (comp/aicomp_sdk) is importable.

The SDK is gitignored and re-fetched via scripts/fetch_sdk.sh; it is not a
pip-installed package, so we put comp/ on sys.path when aicomp_sdk is missing.
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_COMP_DIR = _REPO_ROOT / "comp"


def ensure_sdk_on_path() -> Path:
    """Make `aicomp_sdk` importable and return its package dir."""
    try:
        import aicomp_sdk  # noqa: F401
    except ModuleNotFoundError:
        if not (_COMP_DIR / "aicomp_sdk").is_dir():
            raise RuntimeError(
                f"aicomp_sdk not found. Run scripts/fetch_sdk.sh to download it into {_COMP_DIR}."
            ) from None
        sys.path.insert(0, str(_COMP_DIR))
        import aicomp_sdk  # noqa: F401
    return Path(aicomp_sdk.__file__).resolve().parent
