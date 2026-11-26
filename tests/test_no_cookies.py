"""One HTTP client serves every caller, so nothing a response sets may ride along on the next request."""

from __future__ import annotations

import httpx
import respx

from secobserve_mcp.client import request
from secobserve_mcp.config import request_credential

from .conftest import BASE_URL

API = f"{BASE_URL}/api"
SET_COOKIE = {"Set-Cookie": "sessionid=belongs-to-alice; Path=/; HttpOnly"}


@respx.mock
async def test_a_plain_client_would_replay_the_cookie() -> None:
    """The hazard itself, so the test below cannot pass because httpx stopped keeping cookies."""
    respx.get(f"{API}/users/me/").mock(return_value=httpx.Response(200, json={}, headers=SET_COOKIE))
    second = respx.get(f"{API}/products/").mock(return_value=httpx.Response(200, json={}))

    async with httpx.AsyncClient(base_url=API) as plain:
        await plain.get("/users/me/")
        await plain.get("/products/")

    assert "sessionid=belongs-to-alice" in second.calls.last.request.headers.get("cookie", "")


@respx.mock
async def test_a_cookie_set_for_one_caller_is_not_sent_for_the_next() -> None:
    respx.get(f"{API}/users/me/").mock(return_value=httpx.Response(200, json={}, headers=SET_COOKIE))
    second = respx.get(f"{API}/products/").mock(return_value=httpx.Response(200, json={}))

    with request_credential("APIToken alice"):
        await request("GET", "/users/me/")
    with request_credential("APIToken bob"):
        await request("GET", "/products/")

    sent = second.calls.last.request
    assert "cookie" not in sent.headers
    assert sent.headers["Authorization"] == "APIToken bob"
