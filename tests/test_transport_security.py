"""Host and Origin checks on the HTTP transport, on every bind address rather than only where the SDK applies them."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import pytest

from secobserve_mcp import config, prompts, tools_crud, tools_workflows  # noqa: F401  # registers the tools
from secobserve_mcp.__main__ import _transport_security, main
from secobserve_mcp.app import mcp

INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "probe", "version": "0"}},
}


@asynccontextmanager
async def bound_to_all_interfaces(*extra_hosts: str) -> AsyncIterator[httpx.AsyncClient]:
    """The server as a container runs it: `--host 0.0.0.0`, where the SDK applies no check of its own."""
    app = mcp.streamable_http_app(
        host="0.0.0.0", stateless_http=True, json_response=True, transport_security=_transport_security(extra_hosts)
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8931") as client,
    ):
        yield client


async def post(client: httpx.AsyncClient, **headers: str) -> int:
    response = await client.post(
        "/mcp", json=INITIALIZE, headers={"Accept": "application/json, text/event-stream", **headers}
    )
    return response.status_code


async def test_the_sdk_alone_answers_any_host_on_a_non_loopback_bind() -> None:
    """The reason this module exists; if the SDK starts checking by itself this fails and the reason is gone."""
    app = mcp.streamable_http_app(host="0.0.0.0", stateless_http=True, json_response=True)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8931") as client,
    ):
        assert await post(client, Host="attacker.example:8931") == 200


async def test_a_rebound_name_is_refused_on_a_non_loopback_bind() -> None:
    async with bound_to_all_interfaces() as client:
        assert await post(client, Host="attacker.example:8931") == 421
        assert await post(client, Host="attacker.example") == 421


async def test_a_browser_origin_from_elsewhere_is_refused() -> None:
    async with bound_to_all_interfaces() as client:
        assert await post(client, Host="127.0.0.1:8931", Origin="https://attacker.example") == 403


@pytest.mark.parametrize("host", ["127.0.0.1:8931", "localhost:8931", "localhost", "[::1]:8931"])
async def test_loopback_names_always_pass(host: str) -> None:
    """A published container port is reached as localhost, so the documented `docker run` needs no extra setting."""
    async with bound_to_all_interfaces() as client:
        assert await post(client, Host=host) == 200


async def test_a_listed_name_passes_with_and_without_a_port() -> None:
    async with bound_to_all_interfaces("secobserve-mcp.tools.svc") as client:
        assert await post(client, Host="secobserve-mcp.tools.svc:8931") == 200
        assert await post(client, Host="secobserve-mcp.tools.svc") == 200
        assert await post(client, Host="secobserve-mcp.tools.svc", Origin="https://secobserve-mcp.tools.svc") == 200
        assert await post(client, Host="secobserve-mcp.tools.svc.attacker.example") == 421


async def test_a_name_listed_with_a_port_matches_that_port_only() -> None:
    async with bound_to_all_interfaces("mcp.internal:8931") as client:
        assert await post(client, Host="mcp.internal:8931") == 200
        assert await post(client, Host="mcp.internal:9999") == 421


async def test_the_liveness_probe_is_not_subject_to_the_check() -> None:
    """A kubelet probes by pod address, which nobody can list in advance."""
    async with bound_to_all_interfaces() as client:
        response = await client.get("/healthz", headers={"Host": "10.0.3.7:8931"})

    assert response.status_code == 200


def test_the_setting_is_a_comma_separated_list(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(config.ENV_ALLOWED_HOSTS, " mcp.internal , secobserve-mcp.tools.svc:8931 ,")
    config.get_config.cache_clear()

    assert config.get_config().allowed_hosts == ("mcp.internal", "secobserve-mcp.tools.svc:8931")


@pytest.mark.parametrize(
    "entry", ["https://mcp.internal", "mcp.internal/mcp", "*", "*.internal", "mcp internal", "a:b"]
)
def test_an_entry_that_could_never_match_a_host_header_stops_the_server(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], entry: str
) -> None:
    monkeypatch.setenv(config.ENV_ALLOWED_HOSTS, entry)
    config.get_config.cache_clear()
    monkeypatch.setattr("secobserve_mcp.app.mcp.run", lambda **kwargs: pytest.fail("the server started"))
    monkeypatch.setattr("sys.argv", ["secobserve-mcp"])

    assert main() == 2
    assert config.ENV_ALLOWED_HOSTS in capsys.readouterr().err


def test_main_hands_the_check_to_the_transport_and_says_which_names_it_answers(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr("secobserve_mcp.app.mcp.run", lambda **kwargs: calls.append(kwargs))
    monkeypatch.setenv(config.ENV_ALLOWED_HOSTS, "mcp.internal")
    config.get_config.cache_clear()
    monkeypatch.setattr("sys.argv", ["secobserve-mcp", "--transport", "http", "--host", "0.0.0.0", "--shared-identity"])

    assert main() == 0

    security = calls[0]["transport_security"]
    assert security.enable_dns_rebinding_protection is True  # type: ignore[attr-defined]
    assert "mcp.internal:*" in security.allowed_hosts  # type: ignore[attr-defined]
    stderr = capsys.readouterr().err
    assert "mcp.internal" in stderr and "421" in stderr


def test_a_loopback_bind_says_nothing_extra(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr("secobserve_mcp.app.mcp.run", lambda **kwargs: calls.append(kwargs))
    monkeypatch.setattr("sys.argv", ["secobserve-mcp", "--transport", "http", "--shared-identity"])

    assert main() == 0
    assert "421" not in capsys.readouterr().err
    assert calls[0]["transport_security"].enable_dns_rebinding_protection is True  # type: ignore[attr-defined]
