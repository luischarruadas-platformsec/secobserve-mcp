"""Keep credentials SecObserve stores for other systems out of tool results.

SecObserve returns an API configuration's key and password, a product's issue tracker key and its notification
webhooks to any caller allowed to edit them. A tool result lands in the agent's context and the client's
transcript, which is further than those values were meant to travel, and read-only mode does not stop a read.

The match is on the key's name, not on a list of resources, so a nested copy and a field a later backend adds
under the same naming are covered without a catalogue entry.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[redacted by secobserve-mcp]"

# api_key, issue_tracker_api_key, basic_auth_password, notification_slack_webhook, notification_ms_teams_webhook.
_SECRET_KEY = re.compile(r"(^|_)(api_key|password|webhook)$")


def _is_secret(key: Any, value: Any) -> bool:
    return isinstance(key, str) and isinstance(value, str) and bool(value) and bool(_SECRET_KEY.search(key))


def redact(payload: Any) -> Any:
    """Replace every stored credential in a parsed response with a placeholder; an empty one stays empty."""
    if isinstance(payload, dict):
        return {key: REDACTED if _is_secret(key, value) else redact(value) for key, value in payload.items()}
    if isinstance(payload, list):
        return [redact(item) for item in payload]
    return payload


def carries_placeholder(payload: Any) -> bool:
    """Whether a request body would write the placeholder back over the credential it stands for."""
    if isinstance(payload, dict):
        return any(carries_placeholder(value) for value in payload.values())
    if isinstance(payload, (list, tuple)):
        return any(carries_placeholder(item) for item in payload)
    return payload == REDACTED
