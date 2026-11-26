"""An export is the instance's findings in bulk: only its owner may read it, and it must land where it was meant to."""

from __future__ import annotations

import stat
import sys
from pathlib import Path

import httpx
import pytest
import respx

from secobserve_mcp import config
from secobserve_mcp.exports import write_export
from secobserve_mcp.tools_crud import secobserve_call_action

from .conftest import BASE_URL

API = f"{BASE_URL}/api"

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits and symlinks")


def export_dir() -> Path:
    return Path(config.get_config().export_dir)


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@posix_only
def test_an_export_and_its_new_directory_are_private_to_the_owner() -> None:
    write_export("report", "export_csv", b"a,b\n")

    assert mode(export_dir()) == 0o700
    assert mode(export_dir() / "report.csv") == 0o600


@posix_only
def test_an_export_left_readable_by_an_earlier_version_is_tightened_when_rewritten() -> None:
    export_dir().mkdir(parents=True)
    old = export_dir() / "report.csv"
    old.write_bytes(b"old")
    old.chmod(0o644)

    write_export("report", "export_csv", b"new")

    assert old.read_bytes() == b"new"
    assert mode(old) == 0o600


def test_replacing_an_earlier_export_is_said_out_loud() -> None:
    first = write_export("report", "export_csv", b"one")
    second = write_export("report", "export_csv", b"two")

    assert "replacing an earlier file" not in first
    assert "replacing an earlier file of that name" in second


@posix_only
def test_a_link_in_the_export_directory_is_not_followed(tmp_path: Path) -> None:
    """Followed, the export would overwrite whatever the link points at."""
    outside = tmp_path / "outside.txt"
    outside.write_text("untouched")
    export_dir().mkdir(parents=True)
    (export_dir() / "report.csv").symlink_to(outside)

    with pytest.raises(ValueError, match="symbolic link"):
        write_export("report", "export_csv", b"a,b\n")

    assert outside.read_text() == "untouched"


@posix_only
def test_a_dangling_link_is_refused_too(tmp_path: Path) -> None:
    export_dir().mkdir(parents=True)
    (export_dir() / "report.csv").symlink_to(tmp_path / "does-not-exist-yet")

    with pytest.raises(ValueError, match="symbolic link"):
        write_export("report", "export_csv", b"a,b\n")

    assert not (tmp_path / "does-not-exist-yet").exists()


@posix_only
@respx.mock
async def test_the_refusal_reaches_the_agent_as_text(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("untouched")
    export_dir().mkdir(parents=True)
    (export_dir() / "products-export_observations_csv-12.csv").symlink_to(outside)
    respx.get(f"{API}/products/12/export_observations_csv/").mock(return_value=httpx.Response(200, content=b"a,b\n"))

    result = await secobserve_call_action(resource="products", action="export_observations_csv", id=12)

    assert result.startswith("Error:") and "symbolic link" in result
    assert outside.read_text() == "untouched"
