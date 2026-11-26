"""SECOBSERVE_ALLOW_DELETE has to cover every call that removes records, not only the ones named after it."""

from __future__ import annotations

import httpx
import pytest
import respx

from secobserve_mcp import config
from secobserve_mcp.registry import RESOURCES
from secobserve_mcp.tools_crud import (
    secobserve_call_action,
    secobserve_create,
    secobserve_list_resources,
    secobserve_update,
)
from secobserve_mcp.tools_workflows import secobserve_run_periodic_task

from .conftest import BASE_URL

API = f"{BASE_URL}/api"


def allow_deletes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(config.ENV_ALLOW_DELETE, "true")
    config.get_config.cache_clear()


def refused(result: str) -> bool:
    return result.startswith("Error:") and "SECOBSERVE_ALLOW_DELETE" in result


def test_every_action_named_after_a_delete_is_marked_as_one() -> None:
    unmarked = [
        f"{name}.{action.name}"
        for name, resource in RESOURCES.items()
        for action in resource.actions
        if ("delete" in action.name or action.method == "DELETE") and not action.deletes
    ]

    assert unmarked == []


@respx.mock
async def test_an_import_that_deletes_what_the_results_lack_is_gated() -> None:
    """ScanCode.io import removes every license component missing from the results, under a name that says import."""
    result = await secobserve_call_action(resource="scancodeio_projects", action="import_results", id=3)

    assert refused(result)
    assert not respx.calls


@respx.mock
async def test_the_gated_import_runs_once_deletes_are_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    allow_deletes(monkeypatch)
    route = respx.post(f"{API}/scancodeio_projects/3/import_results/").mock(
        return_value=httpx.Response(200, json={"license_components_deleted": 4})
    )

    result = await secobserve_call_action(resource="scancodeio_projects", action="import_results", id=3)

    assert route.called
    assert "license_components_deleted" in result


async def test_the_catalogue_says_which_actions_are_gated() -> None:
    catalogue = await secobserve_list_resources(contains="scancodeio")

    assert "action `import_results`: POST, detail (needs id), needs SECOBSERVE_ALLOW_DELETE" in catalogue
    assert "action `details`: GET, detail (needs id) --" in catalogue


@respx.mock
async def test_put_is_gated_because_it_blanks_what_the_body_leaves_out() -> None:
    result = await secobserve_update(resource="products", id=12, data={"name": "Portal"}, replace=True)

    assert refused(result) and "PUT" in result
    assert not respx.calls


@respx.mock
async def test_patch_is_not_gated() -> None:
    respx.get(f"{API}/oa3/schema/").mock(return_value=httpx.Response(200, json={"paths": {}}))
    route = respx.patch(f"{API}/products/12/").mock(return_value=httpx.Response(200, json={"id": 12}))

    await secobserve_update(resource="products", id=12, data={"name": "Portal"})

    assert route.called


@respx.mock
@pytest.mark.parametrize(
    ("resource", "data"),
    [
        ("settings", {"branch_housekeeping_keep_inactive_days": 1}),
        ("settings", {"branch_housekeeping_active": True, "branch_housekeeping_exempt_branches": ""}),
        ("products", {"repository_branch_housekeeping_keep_inactive_days": 1}),
        ("branches", {"housekeeping_protect": False}),
    ],
)
async def test_housekeeping_settings_are_gated_because_they_delete_on_a_delay(
    resource: str, data: dict[str, object]
) -> None:
    result = await secobserve_update(resource=resource, id=1, data=data)

    assert refused(result) and "housekeeping" in result
    assert not respx.calls


@respx.mock
async def test_a_new_branch_cannot_be_created_unprotected_by_name_alone() -> None:
    result = await secobserve_create(
        resource="branches", data={"product": 12, "name": "x", "housekeeping_protect": False}
    )

    assert refused(result)
    assert not respx.calls


@respx.mock
async def test_protecting_a_branch_removes_nothing_and_is_not_gated() -> None:
    respx.get(f"{API}/oa3/schema/").mock(return_value=httpx.Response(200, json={"paths": {}}))
    route = respx.patch(f"{API}/branches/7/").mock(return_value=httpx.Response(200, json={"id": 7}))

    await secobserve_update(resource="branches", id=7, data={"housekeeping_protect": True})

    assert route.called


@respx.mock
async def test_housekeeping_settings_pass_once_deletes_are_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    allow_deletes(monkeypatch)
    respx.get(f"{API}/oa3/schema/").mock(return_value=httpx.Response(200, json={"paths": {}}))
    route = respx.patch(f"{API}/settings/1/").mock(return_value=httpx.Response(200, json={"id": 1}))

    await secobserve_update(resource="settings", id=1, data={"branch_housekeeping_keep_inactive_days": 30})

    assert route.called


@respx.mock
@pytest.mark.parametrize("task", ["Housekeeping", "task_branch_housekeeping"])
async def test_running_housekeeping_now_is_gated(task: str) -> None:
    result = await secobserve_run_periodic_task(task=task)

    assert refused(result)
    assert not respx.calls


@respx.mock
async def test_other_tasks_are_not_gated() -> None:
    route = respx.post(f"{API}/periodic_tasks/run/").mock(return_value=httpx.Response(204))

    await secobserve_run_periodic_task(task="calculate_product_metrics")

    assert route.called
