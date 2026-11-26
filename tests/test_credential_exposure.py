"""The credential must not leave the process by accident: not in a repr, and not in clear text without a warning."""

from __future__ import annotations

import pytest

from secobserve_mcp import config
from secobserve_mcp.__main__ import _cleartext_warning, main


def test_the_config_repr_carries_neither_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(config.ENV_API_TOKEN, "token-that-must-not-print")
    monkeypatch.setenv(config.ENV_JWT, "jwt-that-must-not-print")
    config.get_config.cache_clear()
    loaded = config.get_config()

    assert "must-not-print" not in repr(loaded)
    assert "must-not-print" not in str(loaded)
    assert loaded.auth_header == "APIToken token-that-must-not-print"


@pytest.mark.parametrize(
    "base_url",
    [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://[::1]:8000",
        "http://secobserve.localhost:8000",
        "https://secobserve.example.com",
    ],
)
def test_a_local_or_encrypted_base_url_is_not_warned_about(base_url: str) -> None:
    assert _cleartext_warning(base_url) is None


@pytest.mark.parametrize(
    "base_url", ["http://secobserve.example.com", "http://10.0.3.7:8000", "http://localhost.evil.test"]
)
def test_plain_http_to_another_machine_is_warned_about(base_url: str) -> None:
    warning = _cleartext_warning(base_url)

    assert warning is not None and "unencrypted" in warning


def test_the_warning_is_printed_at_startup_and_does_not_stop_the_server(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A cluster-internal http URL is common and deliberate, so this informs and never refuses."""
    calls: list[dict[str, object]] = []
    monkeypatch.setattr("secobserve_mcp.app.mcp.run", lambda **kwargs: calls.append(kwargs))
    monkeypatch.setenv(config.ENV_BASE_URL, "http://secobserve.internal:8000")
    config.get_config.cache_clear()
    monkeypatch.setattr("sys.argv", ["secobserve-mcp"])

    assert main() == 0
    assert calls == [{}]
    stderr = capsys.readouterr().err
    assert "unencrypted" in stderr and "secobserve.internal" in stderr
    assert "test-token" not in stderr
