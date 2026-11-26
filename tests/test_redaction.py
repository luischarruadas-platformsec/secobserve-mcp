"""Credentials SecObserve stores for other systems must not travel into a tool result."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from secobserve_mcp.client import request
from secobserve_mcp.formatting import ResponseFormat
from secobserve_mcp.redaction import REDACTED, carries_placeholder, redact
from secobserve_mcp.tools_crud import secobserve_get, secobserve_list, secobserve_update

from .conftest import BASE_URL

API = f"{BASE_URL}/api"

API_CONFIGURATION = {
    "id": 5,
    "name": "dtrack-portal",
    "base_url": "https://dtrack.example",
    "api_key": "odt_live_key",
    "basic_auth_password": "hunter2",
    "basic_auth_username": "svc",
}

PRODUCT = {
    "id": 12,
    "name": "Portal",
    "issue_tracker_api_key": "ghp_live_key",
    "issue_tracker_base_url": "https://api.github.com",
    "notification_slack_webhook": "https://hooks.slack.example/T0/B0/secret",
    "notification_ms_teams_webhook": "",
    "product_group_data": {"id": 3, "notification_ms_teams_webhook": "https://teams.example/secret"},
}

SECRETS = ("odt_live_key", "hunter2", "ghp_live_key", "hooks.slack.example", "teams.example")


def test_named_credentials_are_replaced_at_any_depth() -> None:
    cleaned = redact({"results": [API_CONFIGURATION, PRODUCT]})

    assert not any(secret in json.dumps(cleaned) for secret in SECRETS)
    assert cleaned["results"][0]["api_key"] == REDACTED
    assert cleaned["results"][1]["product_group_data"]["notification_ms_teams_webhook"] == REDACTED


def test_everything_else_is_left_alone() -> None:
    cleaned = redact({"results": [API_CONFIGURATION, PRODUCT]})

    assert cleaned["results"][0]["base_url"] == "https://dtrack.example"
    assert cleaned["results"][0]["basic_auth_username"] == "svc"
    assert cleaned["results"][1]["issue_tracker_base_url"] == "https://api.github.com"
    # Empty stays empty, so "is a webhook configured" keeps its answer.
    assert cleaned["results"][1]["notification_ms_teams_webhook"] == ""


def test_a_schema_that_only_names_the_field_is_not_touched() -> None:
    schema = {"properties": {"api_key": {"type": "string", "maxLength": 255}}, "required": ["api_key", "password"]}

    assert redact(schema) == schema


@respx.mock
async def test_get_returns_the_placeholder_in_both_formats() -> None:
    respx.get(f"{API}/api_configurations/5/").mock(return_value=httpx.Response(200, json=API_CONFIGURATION))

    for response_format in (ResponseFormat.JSON, ResponseFormat.MARKDOWN):
        text = await secobserve_get(resource="api_configurations", id=5, response_format=response_format)
        assert REDACTED in text
        assert not any(secret in text for secret in SECRETS)


@respx.mock
async def test_list_with_every_field_returns_the_placeholder() -> None:
    respx.get(f"{API}/oa3/schema/").mock(return_value=httpx.Response(200, json={"paths": {}}))
    respx.get(f"{API}/products/").mock(return_value=httpx.Response(200, json={"count": 1, "results": [PRODUCT]}))

    text = await secobserve_list(resource="products", fields=["*"], response_format=ResponseFormat.JSON)

    assert REDACTED in text
    assert not any(secret in text for secret in SECRETS)


@respx.mock
async def test_the_response_to_a_write_is_redacted_too() -> None:
    respx.get(f"{API}/oa3/schema/").mock(return_value=httpx.Response(200, json={"paths": {}}))
    route = respx.patch(f"{API}/api_configurations/5/").mock(return_value=httpx.Response(200, json=API_CONFIGURATION))

    text = await secobserve_update(resource="api_configurations", id=5, data={"api_key": "a-new-real-key"})

    assert json.loads(route.calls.last.request.content) == {"api_key": "a-new-real-key"}
    assert not any(secret in text for secret in SECRETS)


@pytest.mark.parametrize(
    "body",
    [
        {"api_key": REDACTED},
        {"name": "x", "nested": {"basic_auth_password": REDACTED}},
        {"items": [{"notification_slack_webhook": REDACTED}]},
    ],
)
async def test_the_placeholder_is_never_written_back(body: dict[str, object]) -> None:
    """A read-modify-write with PUT would otherwise replace the stored credential with the placeholder."""
    assert carries_placeholder(body)
    # No respx mock: a request escaping the guard would fail as a connection error instead.
    with pytest.raises(ValueError, match="overwrite the real value"):
        await request("PUT", "/api_configurations/5/", json_body=body)


def test_an_ordinary_body_carries_no_placeholder() -> None:
    assert not carries_placeholder({"name": "x", "api_key": "real", "tags": ["a", "b"], "n": 1, "flag": None})
    assert not carries_placeholder(None)
