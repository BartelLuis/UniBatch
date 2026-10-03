"""Reject stale pins and dependency-source/hash bypasses before installation."""
from pathlib import Path

import pytest

from tools.check_requirements import check


HASH = "--hash=sha256:" + "a" * 64


@pytest.fixture
def manifests(tmp_path: Path):
    files = {
        "requirements.txt": "httpx==0.28.1\n",
        "requirements.lock": f"# Reviewed artifacts\nhttpx==0.28.1 \\\n    {HASH}\n",
        "requirements-dev.txt": "-r requirements.txt\npytest==9.1.1\n",
        "requirements-dev.lock": f"-r requirements.lock\npytest==9.1.1 \\\n    {HASH}\n",
    }
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    return tmp_path


def test_current_pins_and_reviewed_hashes_pass(manifests):
    assert check(manifests) == (1, 1)


@pytest.mark.parametrize("filename,replacement", [
    ("requirements.txt", "httpx==0.29.0\n"),
    ("requirements-dev.txt", "-r requirements.txt\npytest==9.2.0\n"),
])
def test_changed_direct_pins_require_a_lock_update(manifests, filename, replacement):
    (manifests / filename).write_text(replacement, encoding="utf-8")
    with pytest.raises(ValueError, match="regenerate the lock"):
        check(manifests)


@pytest.mark.parametrize("filename,replacement", [
    ("requirements.txt", "httpx>=0.28.1\n"),
    ("requirements.txt", "httpx==0.28.*\n"),
    ("requirements.txt", "httpx @ https://unreviewed.example/httpx.whl\n"),
    ("requirements.txt", "--extra-index-url https://unreviewed.example/simple\nhttpx==0.28.1\n"),
    ("requirements.lock", "httpx==0.28.1\n"),
    ("requirements.lock", "httpx==0.28.1 --hash=md5:" + "a" * 32 + "\n"),
    ("requirements.lock", "httpx==0.28.1 --hash=sha256:" + "a" * 63 + "\n"),
    ("requirements.lock", f"httpx==0.28.1 {HASH} --find-links https://unreviewed.example\n"),
    ("requirements.lock", "httpx==0.28.1 \\\n"),
    ("requirements-dev.txt", "-r unreviewed.txt\npytest==9.1.1\n"),
    ("requirements-dev.lock", f"-r unreviewed.lock\npytest==9.1.1 {HASH}\n"),
    ("requirements-dev.lock", f"-r requirements.lock\n-r requirements.lock\npytest==9.1.1 {HASH}\n"),
])
def test_unpinned_sources_invalid_hashes_and_unreviewed_includes_fail(manifests, filename, replacement):
    (manifests / filename).write_text(replacement, encoding="utf-8")
    with pytest.raises(ValueError):
        check(manifests)


def test_development_lock_cannot_override_a_runtime_pin(manifests):
    path = manifests / "requirements-dev.lock"
    path.write_text(path.read_text(encoding="utf-8") + f"httpx==0.29.0 {HASH}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="runtime pins must only be included"):
        check(manifests)


def test_equivalent_dependency_names_cannot_hide_duplicate_pins(manifests):
    path = manifests / "requirements.lock"
    path.write_text(path.read_text(encoding="utf-8") + f"Typing_Extensions==4.16.0 {HASH}\ntyping-extensions==4.16.0 {HASH}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate pin"):
        check(manifests)


def test_runtime_only_does_not_require_development_files(manifests):
    assert check(manifests, runtime_only=True) == (1, 0)
