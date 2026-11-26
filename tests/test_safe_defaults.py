"""A switch that guards something must not pick the unsafe side on a missing or misspelled value."""

from __future__ import annotations

import httpx
import pytest
import respx

from secobserve_mcp import config
from secobserve_mcp.__main__ import main
from secobserve_mcp.client import ReadOnlyError, request

from .conftest import BASE_URL

API = f"{BASE_URL}/api"

SWITCHES = [config.ENV_READ_ONLY, config.ENV_VERIFY_SSL, config.ENV_ALLOW_DELETE, config.ENV_AUDIT_LOG]


async def test_writes_are_refused_when_nothing_is_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(config.ENV_READ_ONLY)
    config.get_config.cache_clear()

    assert config.get_config().read_only is True
    # No respx mock: a request escaping the guard would fail as a connection error instead.
    with pytest.raises(ReadOnlyError, match="SECOBSERVE_READ_ONLY=false"):
        await request("PATCH", "/products/12/", json_body={"name": "x"})


@respx.mock
async def test_reads_still_work_when_nothing_is_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(config.ENV_READ_ONLY)
    config.get_config.cache_clear()
    respx.get(f"{API}/products/12/").mock(return_value=httpx.Response(200, json={"id": 12}))

    assert await request("GET", "/products/12/") == {"id": 12}


@pytest.mark.parametrize("raw", ["1", "true", "TRUE", " yes ", "On"])
def test_the_accepted_spellings_of_on(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    monkeypatch.setenv(config.ENV_ALLOW_DELETE, raw)
    assert config._bool_env(config.ENV_ALLOW_DELETE, False) is True


@pytest.mark.parametrize("raw", ["0", "false", "FALSE", " no ", "Off"])
def test_the_accepted_spellings_of_off(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    monkeypatch.setenv(config.ENV_VERIFY_SSL, raw)
    assert config._bool_env(config.ENV_VERIFY_SSL, True) is False


@pytest.mark.parametrize("raw", ["", "   "])
def test_an_empty_value_is_the_default(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    monkeypatch.setenv(config.ENV_VERIFY_SSL, raw)
    assert config._bool_env(config.ENV_VERIFY_SSL, True) is True


@pytest.mark.parametrize("name", SWITCHES)
@pytest.mark.parametrize("raw", ["enabled", "y", "ture", "'true'", "true # keep on"])
def test_an_unreadable_value_is_refused_rather_than_read_as_off(
    monkeypatch: pytest.MonkeyPatch, name: str, raw: str
) -> None:
    """Read as off, `SECOBSERVE_READ_ONLY=enabled` left writes on and `SECOBSERVE_VERIFY_SSL=ture` disabled TLS checks."""
    monkeypatch.setenv(name, raw)

    with pytest.raises(config.ConfigError, match=name):
        config._bool_env(name, True)


@pytest.mark.parametrize("name", SWITCHES)
def test_the_server_does_not_start_on_an_unreadable_switch(monkeypatch: pytest.MonkeyPatch, capsys, name: str) -> None:
    monkeypatch.setenv(name, "enabled")
    config.get_config.cache_clear()
    monkeypatch.setattr("secobserve_mcp.app.mcp.run", lambda **kwargs: pytest.fail("the server started"))
    monkeypatch.setattr("sys.argv", ["secobserve-mcp"])

    assert main() == 2
    assert name in capsys.readouterr().err


@respx.mock
async def test_an_unreadable_audit_switch_keeps_the_record(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A process that got past startup some other way must not lose its audit line to a typo."""
    from .test_audit_log import audit_lines, call_tool, gateway

    monkeypatch.setenv(config.ENV_AUDIT_LOG, "flase")
    respx.get(f"{API}/products/1/").mock(return_value=httpx.Response(200, json={"id": 1}))

    async with gateway() as client:
        await call_tool(client, "secobserve_get", {"resource": "products", "id": 1}, credential="APIToken x")

    lines, _ = audit_lines(capsys)
    assert [line["tool"] for line in lines] == ["secobserve_get"]
