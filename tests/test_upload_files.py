"""Uploads read local files on an agent's say-so, so what they may read is the operator's decision, never a default."""

from __future__ import annotations

from pathlib import Path

import pytest
import respx

from secobserve_mcp import config
from secobserve_mcp.exports import read_upload
from secobserve_mcp.tools_workflows import secobserve_upload_file


def import_dir() -> Path:
    configured = config.get_config().import_dir
    assert configured
    return Path(configured)


def test_the_working_directory_is_not_an_import_directory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A client launches the server from wherever it likes: a home directory, or a repository with a `.env` in it."""
    monkeypatch.delenv(config.ENV_IMPORT_DIR)
    config.get_config.cache_clear()
    monkeypatch.chdir(tmp_path)
    (tmp_path / "trivy.json").write_text("{}")

    assert config.get_config().import_dir is None
    with pytest.raises(ValueError, match="SECOBSERVE_IMPORT_DIR is not set"):
        read_upload("trivy.json")
    with pytest.raises(ValueError, match="SECOBSERVE_IMPORT_DIR is not set"):
        read_upload(str(tmp_path / "trivy.json"))


@respx.mock
async def test_the_tool_says_uploads_are_off_and_sends_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(config.ENV_IMPORT_DIR)
    config.get_config.cache_clear()

    result = await secobserve_upload_file(kind="observations", file_path="trivy.json", product_id=1)

    assert result.startswith("Error:") and "SECOBSERVE_IMPORT_DIR" in result
    assert not respx.calls


def test_a_report_in_the_import_directory_is_read() -> None:
    (import_dir() / "sub").mkdir()
    (import_dir() / "sub" / "trivy.json").write_text("{}")

    assert read_upload("sub/trivy.json") == ("trivy.json", b"{}")


@pytest.mark.parametrize("path", [".env", ".aws/credentials", "reports/.cache/trivy.json"])
def test_a_hidden_file_or_directory_is_refused(path: str) -> None:
    target = import_dir() / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("AWS_SECRET_ACCESS_KEY=not-a-real-one")

    with pytest.raises(ValueError, match="hidden file or directory"):
        read_upload(path)


def test_a_dot_in_the_import_directory_itself_does_not_count(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The operator chose the root; only what lies under it is the caller's to name."""
    root = tmp_path / ".scans"
    root.mkdir()
    (root / "trivy.json").write_text("{}")
    monkeypatch.setenv(config.ENV_IMPORT_DIR, str(root))
    config.get_config.cache_clear()

    assert read_upload("trivy.json") == ("trivy.json", b"{}")
