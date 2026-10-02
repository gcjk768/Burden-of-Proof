from __future__ import annotations

from pathlib import Path

import pytest

from bop.config import load_settings

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures"


@pytest.fixture
def settings(tmp_path: Path):
    return load_settings({"BOP_HOME": str(tmp_path / "home"), "NEBIUS_API_KEY": "test-key-not-real"})


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES
