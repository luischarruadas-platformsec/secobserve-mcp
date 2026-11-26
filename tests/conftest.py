"""Shared fixtures. Config is cached per process, so each test resets it."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator

import pytest

from secobserve_mcp import client, config

BASE_URL = "http://secobserve.test"


@pytest.fixture(autouse=True)
def reset_state(monkeypatch: pytest.MonkeyPatch, tmp_path) -> Iterator[None]:
    monkeypatch.setenv(config.ENV_BASE_URL, BASE_URL)
    monkeypatch.setenv(config.ENV_API_TOKEN, "test-token")
    monkeypatch.delenv(config.ENV_JWT, raising=False)
    # Read-only is the default; the suite exercises the write paths, so it opts in the way an operator would.
    monkeypatch.setenv(config.ENV_READ_ONLY, "false")
    monkeypatch.delenv(config.ENV_VERIFY_SSL, raising=False)
    monkeypatch.delenv(config.ENV_AUDIT_LOG, raising=False)
    monkeypatch.delenv(config.ENV_ALLOW_DELETE, raising=False)
    monkeypatch.setenv(config.ENV_IMPORT_DIR, str(tmp_path / "in"))
    monkeypatch.setenv(config.ENV_EXPORT_DIR, str(tmp_path / "out"))
    (tmp_path / "in").mkdir()
    config.get_config.cache_clear()
    yield
    asyncio.run(client.close_client())
    config.get_config.cache_clear()
