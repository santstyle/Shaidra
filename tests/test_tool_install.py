"""Tests for utils/tool_install: extract, pick asset, find binary, PATH."""

from __future__ import annotations

import io
import os
import tarfile
import zipfile
from pathlib import Path

from shaidra.utils import tool_install


def test_ensure_on_path_prepends_once(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))
    tool_install.ensure_on_path()
    tool_install.ensure_on_path()
    parts = os.environ["PATH"].split(os.pathsep)
    assert parts.count(str(tool_install.tools_dir())) == 1
    assert parts[0] == str(tool_install.tools_dir())


def test_pick_asset_selects_platform_zip() -> None:
    assets = [
        {"name": "ffuf_1.0_linux_amd64.tar.gz", "browser_download_url": "https://x/linux"},
        {"name": "ffuf_1.0_windows_amd64.zip", "browser_download_url": "https://x/win"},
    ]
    chosen = tool_install._pick_asset(assets, "ffuf", "win32", "amd64")
    assert chosen is not None
    assert "windows" in chosen["name"]


def test_pick_asset_rejects_non_archive() -> None:
    assets = [{"name": "ffuf_checksums.txt", "browser_download_url": "https://x"}]
    assert tool_install._pick_asset(assets, "ffuf", "linux", "amd64") is None


def test_pick_asset_requires_binary_name() -> None:
    assets = [{"name": "other_windows_amd64.zip", "browser_download_url": "https://x"}]
    assert tool_install._pick_asset(assets, "ffuf", "win32", "amd64") is None


def _zip_bytes(name: str, content: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, content)
    return buffer.getvalue()


def _tar_gz_bytes(name: str, content: bytes) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo(name=name)
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def test_extract_zip(tmp_path: Path) -> None:
    files = tool_install._extract("ffuf.zip", _zip_bytes("ffuf", b"bin"), tmp_path)
    assert any(p.name == "ffuf" and p.read_bytes() == b"bin" for p in files)


def test_extract_tar_gz(tmp_path: Path) -> None:
    files = tool_install._extract("ffuf.tar.gz", _tar_gz_bytes("ffuf", b"bin"), tmp_path)
    assert any(p.name == "ffuf" for p in files)


def test_extract_rejects_path_slip(tmp_path: Path) -> None:
    files = tool_install._extract("evil.zip", _zip_bytes("../escape.bin", b"x"), tmp_path)
    assert files == []
    assert not (tmp_path.parent / "escape.bin").exists()


def test_extract_unknown_suffix_returns_empty(tmp_path: Path) -> None:
    assert tool_install._extract("x.rar", b"Rar!", tmp_path) == []


def test_find_binary_exact_and_substring(tmp_path: Path) -> None:
    exact = tmp_path / "ffuf"
    exact.write_bytes(b"1")
    nested = tmp_path / "bin"
    nested.mkdir()
    # substring match: empty suffix only; "ffuf_2.0" has suffix ".0" and is rejected
    inner = nested / "ffuf-linux-amd64"
    inner.write_bytes(b"2")
    assert tool_install._find_binary([nested, exact], "ffuf") == exact
    assert tool_install._find_binary([inner], "ffuf") == inner
    assert tool_install._find_binary([], "ffuf") is None


def test_registry_has_known_tools() -> None:
    assert "nuclei" in tool_install._REGISTRY
    assert "subfinder" in tool_install._REGISTRY
    assert tool_install._REGISTRY["nuclei"].binary == "nuclei"


def test_install_missing_skips_when_all_present(monkeypatch) -> None:
    import asyncio

    async def scenario() -> dict[str, bool]:
        async def notify(_: str) -> None:
            return None

        monkeypatch.setattr(tool_install.shutil, "which", lambda _name: "/usr/bin/true")
        return await tool_install.install_missing(["nuclei", "subfinder"], notify)

    assert asyncio.run(scenario()) == {}


def test_install_missing_marks_unregistered(monkeypatch) -> None:
    import asyncio

    async def scenario() -> dict[str, bool]:
        messages: list[str] = []

        async def notify(message: str) -> None:
            messages.append(message)

        monkeypatch.setattr(tool_install.shutil, "which", lambda _name: None)
        monkeypatch.setattr(tool_install, "_install", _fake_install)
        result = await tool_install.install_missing(["nuclei", "mystery"], notify)
        return result

    async def _fake_install(spec: object, notify: object) -> bool:
        return True

    result = asyncio.run(scenario())
    assert result == {"nuclei": True, "mystery": False}
