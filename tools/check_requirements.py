"""Check direct dependency pins and SHA-256 lock structure without dependencies.

Run before installing packages: python tools/check_requirements.py
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
PIN = re.compile(r"([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9.+!-]*)")
HASH = re.compile(r"--hash=sha256:[0-9a-f]{64}")


def canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def logical_lines(path: Path):
    """Join pip continuations while rejecting incomplete lock entries."""
    parts = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        continued = line.endswith("\\")
        parts.append(line[:-1].strip() if continued else line)
        if not continued:
            yield number, " ".join(parts)
            parts.clear()
    if parts:
        raise ValueError(f"{path.name}: unfinished line continuation")


def read_pins(path: Path, *, locked: bool, include: str | None = None) -> dict[str, str]:
    pins = {}
    includes = []
    for number, line in logical_lines(path):
        where = f"{path.name}:{number}"
        if line.startswith("-r "):
            includes.append(line[3:].strip())
            continue
        fields = line.split()
        match = PIN.fullmatch(fields[0])
        if not match:
            raise ValueError(f"{where}: expected an exact package==version pin")
        name, version = canonical_name(match[1]), match[2]
        if name in pins:
            raise ValueError(f"{where}: duplicate pin for {name}")
        if locked:
            if len(fields) < 2 or any(not HASH.fullmatch(item) for item in fields[1:]):
                raise ValueError(f"{where}: each lock entry needs only valid SHA-256 hashes")
        elif len(fields) != 1:
            raise ValueError(f"{where}: direct requirements must contain only package==version")
        pins[name] = version
    expected = [] if include is None else [include]
    if includes != expected:
        raise ValueError(f"{path.name}: expected includes {expected}, found {includes}")
    if not pins:
        raise ValueError(f"{path.name}: no dependency pins found")
    return pins


def matching_pins(direct: dict[str, str], locked: dict[str, str], source: str):
    for name, version in direct.items():
        if locked.get(name) != version:
            actual = locked.get(name, "missing")
            raise ValueError(f"{source}: {name}=={version} differs from lock ({actual}); regenerate the lock")


def check(root: Path = ROOT, *, runtime_only: bool = False):
    runtime = read_pins(root / "requirements.txt", locked=False)
    runtime_lock = read_pins(root / "requirements.lock", locked=True)
    matching_pins(runtime, runtime_lock, "requirements.txt")
    if runtime_only:
        return len(runtime), 0
    dev = read_pins(root / "requirements-dev.txt", locked=False, include="requirements.txt")
    dev_lock = read_pins(root / "requirements-dev.lock", locked=True, include="requirements.lock")
    duplicated = runtime_lock.keys() & dev_lock.keys()
    if duplicated:
        raise ValueError("requirements-dev.lock: runtime pins must only be included, not repeated: " + ", ".join(sorted(duplicated)))
    matching_pins(dev, runtime_lock | dev_lock, "requirements-dev.txt")
    return len(runtime), len(dev)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-only", action="store_true", help="check only production requirements")
    args = parser.parse_args()
    try:
        runtime, dev = check(runtime_only=args.runtime_only)
    except (OSError, ValueError) as error:
        print(f"Dependency lock check failed: {error}", file=sys.stderr)
        return 1
    print(f"Dependency locks match {runtime} runtime and {dev} development direct pins; SHA-256 entries and includes are valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
