"""A request URL carries filter values and search text, so it must not reach the log."""

from __future__ import annotations

import logging

import httpx
import pytest
import respx

from secobserve_mcp.client import request
from secobserve_mcp.tools_crud import secobserve_list

from .conftest import BASE_URL

API = f"{BASE_URL}/api"


@respx.mock
async def test_a_request_url_is_not_logged_at_the_level_the_sdk_configures(caplog: pytest.LogCaptureFixture) -> None:
    """The SDK calls `logging.basicConfig(level=INFO)`, which is where httpx logs `HTTP Request: GET <url>`."""
    caplog.set_level(logging.INFO)
    respx.get(f"{API}/oa3/schema/").mock(return_value=httpx.Response(200, json={"paths": {}}))
    respx.get(f"{API}/observations/").mock(return_value=httpx.Response(200, json={"count": 0, "results": []}))

    await secobserve_list(resource="observations", filters={"title": "ACME-CONFIDENTIAL"}, search="customer-name")

    assert "ACME-CONFIDENTIAL" not in caplog.text
    assert "customer-name" not in caplog.text
    assert "HTTP Request" not in caplog.text


@respx.mock
async def test_a_warning_from_httpx_still_gets_through(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    respx.get(f"{API}/status/version/").mock(return_value=httpx.Response(200, json={}))

    await request("GET", "/status/version/")
    logging.getLogger("httpx").warning("something worth reading")

    assert "something worth reading" in caplog.text
