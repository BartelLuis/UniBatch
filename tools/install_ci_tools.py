"""Install pinned CI binaries after verifying official release SHA-256 hashes."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import tarfile
import tempfile
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 128 * 1024 * 1024
TOOLS = ("actionlint", "hadolint", "gitleaks")


def platform_key(system: str, machine: str) -> str:
    if machine.lower() not in ("amd64", "x86_64") or system.lower() not in ("linux", "windows"):
        raise ValueError("CI tools support only Linux/Windows x86-64")
    return f"{system.lower()}-x64"


def validate_artifact(tool: str, spec: dict, target: str) -> None:
    if not isinstance(spec, dict) or any(not isinstance(spec.get(key), str) for key in ("url", "sha256", "member", "archive")):
        raise ValueError("Release artifact fields must be strings")
    url = urlsplit(spec["url"])
    if (url.scheme != "https" or url.netloc != "github.com" or url.query or url.fragment
            or not re.fullmatch(r"/[\w.-]+/[\w.-]+/releases/download/[^/]+/[^/]+", url.path)):
        raise ValueError("Download must be an HTTPS GitHub release asset")
    if not re.fullmatch(r"[0-9a-f]{64}", spec["sha256"]):
        raise ValueError("A pinned SHA-256 hash is required")
    expected = tool + (".exe" if target == "windows-x64" else "")
    if spec["member"] != expected or spec["archive"] not in ("binary", "zip", "tar.gz"):
        raise ValueError("Unexpected binary name or archive type")


def download(url: str) -> bytes:
    # The caller validates an HTTPS-only GitHub release URL before this request.
    request = Request(url, headers={"User-Agent": "UniBatch-CI-tools"})
    with urlopen(request, timeout=60) as response:  # nosec B310
        if urlsplit(response.url).scheme != "https":
            raise ValueError("Download redirect must remain HTTPS")
        payload = response.read(MAX_BYTES + 1)
    if not payload or len(payload) > MAX_BYTES:
        raise ValueError("Empty or oversized release asset")
    return payload


def binary_contents(payload: bytes, spec: dict) -> bytes:
    # Verify the complete asset before parsing any archive contents.
    if hashlib.sha256(payload).hexdigest() != spec["sha256"]:
        raise ValueError("Release checksum mismatch; binary was not installed")
    member = spec["member"]
    if spec["archive"] == "binary":
        binary = payload
    elif spec["archive"] == "zip":
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            matches = [entry for entry in archive.infolist() if entry.filename == member]
            if len(matches) != 1 or matches[0].is_dir() or matches[0].file_size > MAX_BYTES:
                raise ValueError("Archive must contain one regular expected binary")
            entry = matches[0]
            if entry.orig_filename != member or entry.external_attr & 0x10:
                raise ValueError("Archive binary must have the exact filename and must not be a directory")
            mode = (entry.external_attr >> 16) & 0o170000
            if mode not in (0, 0o100000):
                raise ValueError("Archive binary must not be a link or special file")
            binary = archive.read(entry)
    else:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            matches = [entry for entry in archive.getmembers() if entry.name == member]
            if len(matches) != 1 or not matches[0].isfile() or matches[0].size > MAX_BYTES:
                raise ValueError("Archive must contain one regular expected binary")
            source = archive.extractfile(matches[0])
            if source is None:
                raise ValueError("Archive binary cannot be read")
            with source:
                binary = source.read(MAX_BYTES + 1)
    if not binary or len(binary) > MAX_BYTES:
        raise ValueError("Empty or oversized binary")
    return binary


def install(tool: str, root: Path = ROOT, target: str | None = None) -> Path:
    if tool not in TOOLS:
        raise ValueError("Unknown CI tool")
    target = target or platform_key(platform.system(), platform.machine())
    if target not in ("linux-x64", "windows-x64"):
        raise ValueError("Unsupported platform")
    manifest = json.loads((root / ".github" / "ci-tools.json").read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 1:
        raise ValueError("Unsupported CI tool manifest version")
    try:
        spec = manifest["tools"][tool]["platforms"][target]
    except (KeyError, TypeError):
        raise ValueError("Missing or invalid CI tool platform configuration") from None
    validate_artifact(tool, spec, target)
    binary = binary_contents(download(spec["url"]), spec)
    directory = root / "artifacts" / "ci-tools"
    if not directory.resolve().is_relative_to(root.resolve()):
        raise ValueError("CI tool installation directory must remain within the workspace")
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / spec["member"]
    # Only the expected binary is copied; no archive paths are extracted.
    fd, temporary = tempfile.mkstemp(prefix=f".{tool}-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(binary)
        os.chmod(temporary, 0o700)
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tools", nargs="+", choices=TOOLS)
    args = parser.parse_args()
    try:
        for tool in args.tools:
            print(f"Installed verified {tool}: {install(tool).relative_to(ROOT)}")
    except (ValueError, KeyError, OSError, tarfile.TarError, zipfile.BadZipFile) as error:
        parser.exit(1, f"CI tool installation failed: {error}\n")


if __name__ == "__main__":
    main()
