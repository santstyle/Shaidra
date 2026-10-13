"""Best-effort installer for the external security tools Shaidra can drive.

Without these binaries Shaidra falls back to its own engine, but detection is
strictly better with them, so ``shaidra --install-tools`` fetches the missing
ones. Each tool is installed from its official GitHub release archive (a
prebuilt binary, no compiler needed) and, when that fails, via ``go install``
if a Go toolchain is present. Binaries land in a Shaidra-owned directory that
is prepended to ``PATH`` for the rest of the process.

Downloads are pulled only from the pinned repositories below, and only when the
user explicitly asks for an install — nothing is fetched during a normal scan.
"""

from __future__ import annotations

import asyncio
import io
import os
import platform
import shutil
import sys
import tarfile
import tempfile
import zipfile
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import httpx

Notify = Callable[[str], Awaitable[None]]

_GITHUB_API: Final[str] = "https://api.github.com/repos/{repo}/releases/latest"
_MANUAL: Final[str] = "no automatic installer available; install it manually"


@dataclass(frozen=True, slots=True)
class _Spec:
    """How to obtain one tool: its release repo and Go module path."""

    binary: str
    repo: str
    module: str


# Only tools distributed as a single prebuilt binary (release archive) or via a
# stable Go module are listed; everything else must be installed by hand.
_REGISTRY: Final[dict[str, _Spec]] = {
    "subfinder": _Spec("subfinder", "projectdiscovery/subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"),
    "httpx": _Spec("httpx", "projectdiscovery/httpx", "github.com/projectdiscovery/httpx/cmd/httpx"),
    "naabu": _Spec("naabu", "projectdiscovery/naabu", "github.com/projectdiscovery/naabu/v2/cmd/naabu"),
    "katana": _Spec("katana", "projectdiscovery/katana", "github.com/projectdiscovery/katana/cmd/katana"),
    "nuclei": _Spec("nuclei", "projectdiscovery/nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"),
    "dalfox": _Spec("dalfox", "hahwul/dalfox", "github.com/hahwul/dalfox/v2"),
    "gau": _Spec("gau", "lc/gau", "github.com/lc/gau/v2/cmd/gau"),
    "ffuf": _Spec("ffuf", "ffuf/ffuf", "github.com/ffuf/ffuf/v2"),
    "feroxbuster": _Spec("feroxbuster", "epi052/feroxbuster", ""),
    "gowitness": _Spec("gowitness", "sensepost/gowitness", "github.com/sensepost/gowitness"),
    "trufflehog": _Spec("trufflehog", "trufflesecurity/trufflehog", "github.com/trufflesecurity/trufflehog/v3"),
    "waybackurls": _Spec("waybackurls", "tomnomnom/waybackurls", "github.com/tomnomnom/waybackurls"),
    "assetfinder": _Spec("assetfinder", "tomnomnom/assetfinder", "github.com/tomnomnom/assetfinder"),
    "subjack": _Spec("subjack", "haccer/subjack", "github.com/haccer/subjack"),
    "kiterunner": _Spec("kr", "assetnote/kiterunner", "github.com/assetnote/kiterunner/cmd/kr"),
    "kr": _Spec("kr", "assetnote/kiterunner", "github.com/assetnote/kiterunner/cmd/kr"),
}

_PLATFORM_TOKENS: Final[dict[str, tuple[str, ...]]] = {
    "win32": ("windows",),
    "darwin": ("macos", "darwin", "osx", "apple"),
    "linux": ("linux",),
}
_ARCH_TOKENS: Final[dict[str, tuple[str, ...]]] = {
    "amd64": ("amd64", "x86_64", "64bit"),
    "x86_64": ("amd64", "x86_64", "64bit"),
    "arm64": ("arm64", "aarch64"),
    "aarch64": ("arm64", "aarch64"),
}
_ARCHIVE_SUFFIXES: Final[tuple[str, ...]] = (".zip", ".tar.gz", ".tgz")


def tools_dir() -> Path:
    """Return the Shaidra-owned directory where installed binaries live."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    else:
        base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "shaidra" / "bin"


def ensure_on_path() -> None:
    """Prepend the tools directory to PATH so ``shutil.which`` finds it."""
    directory = str(tools_dir())
    parts = os.environ.get("PATH", "").split(os.pathsep)
    if directory not in parts:
        os.environ["PATH"] = directory + os.pathsep + os.environ.get("PATH", "")


async def install_missing(known: Sequence[str], notify: Notify) -> dict[str, bool]:
    """Install every tool in ``known`` that is missing and installable."""
    ensure_on_path()
    missing = [name for name in known if shutil.which(name) is None]
    if not missing:
        await notify("all known tools are already installed")
        return {}
    await notify(f"installing {len(missing)} missing tool(s) into {tools_dir()}")
    results: dict[str, bool] = {}
    seen: set[str] = set()
    for name in missing:
        spec = _REGISTRY.get(name)
        if spec is None:
            await notify(f"{name}: {_MANUAL}")
            results[name] = False
            continue
        if spec.binary in seen:
            results[name] = results.get(name, True)
            continue
        seen.add(spec.binary)
        results[name] = await _install(spec, notify)
    return results


async def install_names(names: Sequence[str], notify: Notify) -> dict[str, bool]:
    """Install the named tools explicitly (used by repeated ``--install-tools``)."""
    ensure_on_path()
    results: dict[str, bool] = {}
    for name in names:
        spec = _REGISTRY.get(name)
        if spec is None:
            await notify(f"{name}: {_MANUAL}")
            results[name] = False
            continue
        results[name] = await _install(spec, notify)
    return results


async def _install(spec: _Spec, notify: Notify) -> bool:
    target = tools_dir()
    target.mkdir(parents=True, exist_ok=True)
    binary = spec.binary + (".exe" if sys.platform == "win32" else "")
    if (target / binary).is_file():
        await notify(f"{spec.binary}: already installed")
        return True
    if await _install_from_release(spec, target, notify):
        return True
    if await _install_from_go(spec, target, notify):
        return True
    await notify(f"{spec.binary}: could not install automatically (no release asset and no Go toolchain)")
    return False


async def _install_from_release(spec: _Spec, target: Path, notify: Notify) -> bool:
    system = sys.platform if sys.platform in _PLATFORM_TOKENS else "linux"
    machine = platform.machine().lower()
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.get(
                _GITHUB_API.format(repo=spec.repo),
                headers={"User-Agent": "shaidra-installer", "Accept": "application/vnd.github+json"},
            )
            if response.status_code != 200:
                return False
            assets = response.json().get("assets", [])
            chosen = _pick_asset(assets, spec.binary, system, machine)
            if chosen is None:
                return False
            download = chosen.get("url")
            if not isinstance(download, str):
                return False
            archive = await client.get(download)
            if archive.status_code != 200:
                return False
    except (httpx.HTTPError, ValueError):
        return False
    with tempfile.TemporaryDirectory(prefix="shaidra-tool-") as tmp:
        extracted = _extract(chosen.get("name", ""), archive.content, Path(tmp))
        found = _find_binary(extracted, spec.binary)
        if found is None:
            return False
        destination = _place(found, target, spec.binary)
        if not destination.is_file():
            return False
    await notify(f"{spec.binary}: installed from {spec.repo} release")
    return True


async def _install_from_go(spec: _Spec, target: Path, notify: Notify) -> bool:
    go = shutil.which("go")
    if go is None or not spec.module:
        return False
    env = os.environ.copy()
    env["GOBIN"] = str(target)
    env["CGO_ENABLED"] = "0"
    try:
        process = await asyncio.create_subprocess_exec(
            go, "install", spec.module + "@latest",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env,
        )
        _, stderr = await process.communicate()
    except OSError:
        return False
    if process.returncode != 0:
        detail = stderr.decode("utf-8", "replace").strip().splitlines()
        await notify(f"{spec.binary}: go install failed ({detail[-1] if detail else 'unknown error'})")
        return False
    binary = spec.binary + (".exe" if sys.platform == "win32" else "")
    if not (target / binary).is_file():
        await notify(f"{spec.binary}: go install produced no binary")
        return False
    await notify(f"{spec.binary}: installed via go install")
    return True


def _pick_asset(assets: object, binary: str, system: str, machine: str) -> dict[str, str] | None:
    if not isinstance(assets, list):
        return None
    platforms = _PLATFORM_TOKENS.get(system, ())
    arches = _ARCH_TOKENS.get(machine, ())
    best: dict[str, str] | None = None
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = str(asset.get("name", "")).lower()
        if not name.endswith(_ARCHIVE_SUFFIXES):
            continue
        if binary.lower() not in name:
            continue
        if platforms and not any(token in name for token in platforms):
            continue
        if arches and not any(token in name for token in arches):
            continue
        best = {"name": str(asset.get("name", "")), "url": str(asset.get("browser_download_url", ""))}
        if system == "win32" and name.endswith(".zip"):
            break
    return best


def _extract(name: str, payload: bytes, dest: Path) -> list[Path]:
    lowered = name.lower()
    files: list[Path] = []
    if lowered.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            for member in archive.infolist():
                target = _safe_member(dest, member.filename)
                if target is None:
                    continue
                archive.extract(member, dest)
                files.append(target)
        return [path for path in files if path.is_file()]
    if lowered.endswith((".tar.gz", ".tgz")):
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                target = _safe_member(dest, member.name)
                if target is None:
                    continue
                archive.extract(member, dest)
                files.append(target)
        return [path for path in files if path.is_file()]
    return []


def _safe_member(dest: Path, member: str) -> Path | None:
    """Reject archive members that would escape ``dest`` (tar/zip slip)."""
    candidate = (dest / member).resolve()
    try:
        candidate.relative_to(dest.resolve())
    except ValueError:
        return None
    return candidate


def _find_binary(files: Sequence[Path], binary: str) -> Path | None:
    wanted = binary.lower()
    for path in files:
        if path.name.lower() in (wanted, wanted + ".exe"):
            return path
    for path in files:
        if path.suffix.lower() not in ("", ".exe"):
            continue
        if wanted in path.name.lower():
            return path
    return None


def _place(source: Path, target: Path, binary: str) -> Path:
    destination = target / (binary + (".exe" if sys.platform == "win32" else ""))
    shutil.copy2(source, destination)
    if sys.platform != "win32":
        os.chmod(destination, 0o755)
    return destination
