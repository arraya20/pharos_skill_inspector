"""Skill loader: turn a directory / file / zip into Components.

Understands the Pharos Skill Engine layout (SKILL.md entry point, assets/,
references/) but works on any directory or single file.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Component

# Map file extensions to a component "kind".
_EXT_KIND = {
    ".md": "markdown",
    ".markdown": "markdown",
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".sol": "solidity",
    ".json": "json",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".txt": "text",
    ".cfg": "text",
    ".ini": "text",
    ".toml": "text",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".tpl": "template",
    ".env": "text",
}

# Executable / script-bearing kinds: presence raises the risk multiplier.
_EXECUTABLE_KINDS = {"python", "javascript", "typescript", "shell", "solidity", "template"}

# Files/dirs we never scan.
_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build", ".idea"}
_MAX_FILE_BYTES = 2_000_000  # 2 MB safety cap per file

# Zip-extraction safety caps (guard against decompression bombs).
_MAX_EXTRACTED_BYTES = 100_000_000  # 100 MB cap on cumulative uncompressed size
_MAX_ZIP_ENTRIES = 10_000           # refuse pathologically large archives

# Directory-scan safety caps (apply to local dirs and cloned repos alike).
_MAX_TOTAL_FILES = 5_000            # max files read in a single scan
_MAX_TOTAL_BYTES = 200_000_000      # 200 MB cumulative across all scanned files

# Remote-source handling (URLs / git repos / remote zips).
_URL_RE = re.compile(r"^(https?|git|ssh)://", re.IGNORECASE)
_CLONE_TIMEOUT = 120          # seconds
_MAX_DOWNLOAD_BYTES = 50_000_000  # 50 MB cap for remote zip downloads


def is_url(source: str) -> bool:
    """True if ``source`` is a remote URL (http/https/git/ssh) or scp-style git."""
    return bool(_URL_RE.match(source)) or source.startswith("git@")


def _looks_like_zip_url(source: str) -> bool:
    return source.lower().split("?", 1)[0].endswith(".zip")


def _git_clone(url: str, dest: Path) -> None:
    """Shallow-clone a git repo into ``dest``. Raises RuntimeError on failure."""
    cmd = ["git", "clone", "--depth", "1", "--single-branch", "--no-tags", url, str(dest)]
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "true"}
    try:
        proc = subprocess.run(
            cmd, env=env, capture_output=True, text=True, timeout=_CLONE_TIMEOUT,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("git is not installed; cannot clone remote repositories.") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"git clone timed out after {_CLONE_TIMEOUT}s: {url}") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        msg = detail[-1] if detail else "unknown error"
        raise RuntimeError(f"git clone failed for {url}: {msg}")


def _download_zip(url: str, dest_file: Path) -> None:
    """Download a remote .zip to ``dest_file`` with a size cap. http(s) only."""
    if not url.lower().startswith(("http://", "https://")):
        raise RuntimeError(f"Refusing to download non-http(s) URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "pharos-skill-inspector"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp, open(dest_file, "wb") as out:
            total = 0
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_DOWNLOAD_BYTES:
                    raise RuntimeError(
                        f"Remote archive exceeds {_MAX_DOWNLOAD_BYTES} bytes: {url}")
                out.write(chunk)
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Failed to download {url}: {exc.reason}") from exc


def _fetch_remote(source: str) -> tuple[Path, tempfile.TemporaryDirectory]:
    """Materialise a remote source locally.

    Returns ``(local_path, tempdir)`` where ``local_path`` is either a cloned
    directory or a downloaded ``.zip`` file, and ``tempdir`` owns the lifetime
    of the fetched data (cleaned up via :meth:`LoadedSkill.cleanup`).
    """
    tempdir = tempfile.TemporaryDirectory(prefix="psi_")
    base = Path(tempdir.name)
    try:
        if _looks_like_zip_url(source):
            archive = base / "archive.zip"
            _download_zip(source, archive)
            return archive, tempdir
        # Default for http(s)/git/ssh URLs: treat as a git repository.
        repo = base / "repo"
        _git_clone(source, repo)
        return repo, tempdir
    except Exception:
        tempdir.cleanup()
        raise


@dataclass
class LoadedSkill:
    name: str
    source: str
    root: Path
    components: list[Component] = field(default_factory=list)
    skill_md: Component | None = None
    frontmatter: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    _tempdir: tempfile.TemporaryDirectory | None = field(default=None, repr=False)

    def cleanup(self) -> None:
        if self._tempdir is not None:
            self._tempdir.cleanup()
            self._tempdir = None


def _kind_for(path: Path) -> str:
    return _EXT_KIND.get(path.suffix.lower(), "text")


def _read_text(path: Path) -> tuple[str, str | None]:
    """Return (text, error). Binary / oversized files yield empty text."""
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return "", f"{path.name}: skipped (larger than {_MAX_FILE_BYTES} bytes)"
        data = path.read_bytes()
        if b"\x00" in data[:4096]:
            return "", None  # binary, silently skip content
        return data.decode("utf-8", errors="replace"), None
    except OSError as exc:
        return "", f"{path}: {exc}"


def _is_executable_file(path: Path, kind: str) -> bool:
    if kind in _EXECUTABLE_KINDS:
        return True
    # Mark files with the executable bit set as executable.
    try:
        return bool(path.stat().st_mode & 0o111) and path.is_file()
    except OSError:
        return False


def parse_frontmatter(text: str) -> dict[str, Any]:
    """Parse a minimal YAML-ish frontmatter block delimited by '---'.

    Avoids a YAML dependency; handles simple ``key: value`` pairs and inline
    ``[a, b]`` lists which is all the Skill Engine SKILL.md frontmatter uses.
    """
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end == -1:
        return {}
    block = text[3:end].strip("\n")
    out: dict[str, Any] = {}
    for line in block.splitlines():
        line = line.rstrip()
        if not line or line.lstrip().startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if value.startswith("[") and value.endswith("]"):
            items = [v.strip().strip('"').strip("'") for v in value[1:-1].split(",")]
            out[key] = [i for i in items if i]
        else:
            out[key] = value
    return out


def _iter_files(root: Path):
    """Yield regular files under ``root``, skipping skip-dirs and symlinks.

    Symlinked files and directories are never followed: a malicious skill (or a
    cloned repo) could otherwise point a symlink at ``/etc/passwd`` or anywhere
    outside the scan root and have its contents read into a Component.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        # Drop skip-dirs and any symlinked directories (don't descend them).
        dirnames[:] = [
            d for d in dirnames
            if d not in _SKIP_DIRS and not (Path(dirpath) / d).is_symlink()
        ]
        for name in filenames:
            fpath = Path(dirpath) / name
            if fpath.is_symlink():
                continue  # never read through a symlink
            yield fpath


def _safe_extract_zip(zip_path: Path, extract_root: Path) -> None:
    """Extract a zip into ``extract_root``, guarding against the common
    archive attacks:

      * **Zip Slip / path traversal** — entries that resolve outside
        ``extract_root`` are rejected (``foo/../../etc``, absolute paths).
      * **Symlinks** — symlink entries are rejected outright; they can redirect
        later writes outside the tree or leak host files.
      * **Decompression bombs** — the entry count and cumulative *uncompressed*
        size are capped.

    The whole archive is validated before anything is written, so a single bad
    entry aborts the extraction without leaving partial/unsafe files behind.
    """
    base = extract_root.resolve()
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        if len(infos) > _MAX_ZIP_ENTRIES:
            raise ValueError(
                f"Zip archive has too many entries ({len(infos)} > {_MAX_ZIP_ENTRIES}).")
        total = 0
        for info in infos:
            # Unix mode is stored in the high 16 bits of external_attr.
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise ValueError(f"Refusing to extract symlink from zip: {info.filename}")
            dest = (base / info.filename).resolve()
            if not dest.is_relative_to(base):
                raise ValueError(f"Unsafe path in zip: {info.filename}")
            total += info.file_size
            if total > _MAX_EXTRACTED_BYTES:
                raise ValueError(
                    f"Zip archive exceeds extraction cap of {_MAX_EXTRACTED_BYTES} bytes.")
        zf.extractall(extract_root)


def load(source: str) -> LoadedSkill:
    """Load a skill from a directory, single file, zip archive, or remote URL.

    Remote sources (http/https/git/ssh URLs, or ``...zip`` URLs) are fetched
    into a temporary directory that is cleaned up by :meth:`LoadedSkill.cleanup`.
    """
    tempdir: tempfile.TemporaryDirectory | None = None
    display_source = source

    if is_url(source):
        local_path, tempdir = _fetch_remote(source)
        src_path = local_path
    else:
        src_path = Path(source).expanduser()
        if not src_path.exists():
            raise FileNotFoundError(f"Source not found: {source}")
        display_source = str(src_path)

    if src_path.is_file() and src_path.suffix.lower() == ".zip":
        if tempdir is None:
            tempdir = tempfile.TemporaryDirectory(prefix="psi_")
        extract_root = Path(tempdir.name) / "_extracted"
        extract_root.mkdir(exist_ok=True)
        _safe_extract_zip(src_path, extract_root)
        root = extract_root
        # If the zip wrapped everything in a single top-level dir, descend.
        entries = [p for p in root.iterdir() if p.name not in _SKIP_DIRS]
        if len(entries) == 1 and entries[0].is_dir():
            root = entries[0]
        name = Path(source).stem
        file_iter = list(_iter_files(root))
    elif src_path.is_file():
        root = src_path.parent
        name = src_path.stem if src_path.name.lower() != "skill.md" else src_path.parent.name
        file_iter = [src_path]
    else:
        root = src_path
        name = src_path.name
        file_iter = list(_iter_files(root))

    # Derive a friendlier name for cloned repos (last URL path segment).
    if is_url(source):
        seg = source.rstrip("/").split("/")[-1]
        name = re.sub(r"\.(git|zip)$", "", seg) or name

    skill = LoadedSkill(name=name, source=display_source, root=root, _tempdir=tempdir)

    total_files = 0
    total_bytes = 0
    for fpath in sorted(file_iter):
        if total_files >= _MAX_TOTAL_FILES:
            skill.errors.append(
                f"scan truncated: more than {_MAX_TOTAL_FILES} files in source")
            break
        kind = _kind_for(fpath)
        text, err = _read_text(fpath)
        if err:
            skill.errors.append(err)
        total_files += 1
        total_bytes += len(text)
        try:
            rel = str(fpath.relative_to(root))
        except ValueError:
            rel = fpath.name
        comp = Component(
            path=rel,
            kind=kind,
            lines=text.count("\n") + 1 if text else 0,
            executable=_is_executable_file(fpath, kind),
            text=text,
        )
        skill.components.append(comp)
        if fpath.name.lower() == "skill.md" and skill.skill_md is None:
            skill.skill_md = comp
            skill.frontmatter = parse_frontmatter(text)
        if total_bytes > _MAX_TOTAL_BYTES:
            skill.errors.append(
                f"scan truncated: cumulative content exceeds {_MAX_TOTAL_BYTES} bytes")
            break

    if skill.skill_md is not None and skill.frontmatter.get("name"):
        skill.name = str(skill.frontmatter["name"])

    return skill


def has_executable(components: list[Component]) -> bool:
    return any(c.executable for c in components)
