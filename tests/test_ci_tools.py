"""Verified CI binaries are installed atomically without extracting archive paths."""
from __future__ import annotations

import hashlib
import io
import json
import stat
import tarfile
import zipfile

import pytest

from tools import install_ci_tools as installer


BINARY = b"verified-ci-binary"
RELEASE = "https://github.com/example/actionlint/releases/download/v1/actionlint.tar.gz"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("CI tool regression tests must not access the network")
    monkeypatch.setattr(installer, "urlopen", forbidden)


def specification(payload, member="actionlint", archive="binary"):
    return {"url": RELEASE, "sha256": hashlib.sha256(payload).hexdigest(), "member": member, "archive": archive}


def manifest(root, spec, target="linux-x64", *, version=1):
    directory = root / ".github"
    directory.mkdir(parents=True, exist_ok=True)
    value = {"schema_version": version, "tools": {"actionlint": {"version": "1", "platforms": {target: spec}}}}
    (directory / "ci-tools.json").write_text(json.dumps(value), encoding="utf-8")


def zip_asset(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content, mode in entries:
            entry = zipfile.ZipInfo(name)
            entry.create_system = 3
            entry.external_attr = mode << 16
            archive.writestr(entry, content)
    return stream.getvalue()


def tar_asset(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, content, kind in entries:
            entry = tarfile.TarInfo(name)
            entry.type = kind
            if kind == tarfile.REGTYPE:
                entry.size = len(content)
                archive.addfile(entry, io.BytesIO(content))
            else:
                entry.linkname = "../outside"
                archive.addfile(entry)
    return stream.getvalue()


@pytest.mark.parametrize("system,machine,expected", [
    ("Linux", "x86_64", "linux-x64"), ("linux", "AMD64", "linux-x64"),
    ("Windows", "AMD64", "windows-x64"), ("WINDOWS", "x86_64", "windows-x64"),
])
def test_platform_selection(system, machine, expected):
    assert installer.platform_key(system, machine) == expected


@pytest.mark.parametrize("system,machine", [("Darwin", "x86_64"), ("Linux", "arm64"), ("Windows", "x86")])
def test_unsupported_platforms_fail_closed(system, machine):
    with pytest.raises(ValueError, match="Linux/Windows x86-64"):
        installer.platform_key(system, machine)


def test_committed_manifest_has_verified_artifacts_for_both_platforms():
    actual = json.loads((installer.ROOT / ".github" / "ci-tools.json").read_text(encoding="utf-8"))
    assert actual["schema_version"] == 1
    assert set(actual["tools"]) == set(installer.TOOLS)
    for tool, config in actual["tools"].items():
        assert set(config["platforms"]) == {"linux-x64", "windows-x64"}
        for target, spec in config["platforms"].items():
            installer.validate_artifact(tool, spec, target)


@pytest.mark.parametrize("archive_type", ["zip", "tar.gz"])
def test_checksum_mismatch_precedes_any_archive_parser(monkeypatch, archive_type):
    def forbidden(*args, **kwargs):
        pytest.fail("Archive parser ran before checksum verification")
    monkeypatch.setattr(installer.zipfile, "ZipFile", forbidden)
    monkeypatch.setattr(installer.tarfile, "open", forbidden)
    spec = specification(b"expected", archive=archive_type)
    with pytest.raises(ValueError, match="checksum mismatch"):
        installer.binary_contents(b"untrusted", spec)


@pytest.mark.parametrize("target,member", [("linux-x64", "actionlint"), ("windows-x64", "actionlint.exe")])
def test_install_selects_platform_and_preserves_only_expected_binary(tmp_path, monkeypatch, target, member):
    spec = specification(BINARY, member=member)
    manifest(tmp_path, spec, target)
    monkeypatch.setattr(installer.platform, "system", lambda: "Windows" if target.startswith("windows") else "Linux")
    monkeypatch.setattr(installer.platform, "machine", lambda: "AMD64")
    downloaded = []
    monkeypatch.setattr(installer, "download", lambda url: downloaded.append(url) or BINARY)
    destination = installer.install("actionlint", root=tmp_path)
    assert destination == tmp_path / "artifacts" / "ci-tools" / member
    assert destination.read_bytes() == BINARY
    assert downloaded == [RELEASE]
    assert list(destination.parent.iterdir()) == [destination]


@pytest.mark.parametrize("member", ["../actionlint", "/actionlint", "other", "actionlint.exe"])
def test_wrong_or_traversing_binary_name_blocks_download_and_install(tmp_path, member):
    manifest(tmp_path, specification(BINARY, member=member))
    with pytest.raises(ValueError, match="Unexpected binary name"):
        installer.install("actionlint", root=tmp_path, target="linux-x64")
    assert not (tmp_path / "artifacts").exists()


@pytest.mark.parametrize("url", [
    "http://github.com/example/tool/releases/download/v1/tool",
    "https://evil.example/example/tool/releases/download/v1/tool",
    "https://github.com@evil.example/example/tool/releases/download/v1/tool",
    "https://github.com/example/tool/releases/download/v1/tool?token=x",
    "https://github.com/example/tool/releases/download/v1/tool#fragment",
    "https://github.com/example/tool/raw/main/tool",
])
def test_only_https_github_release_assets_allowed(url):
    spec = specification(BINARY)
    spec["url"] = url
    with pytest.raises(ValueError, match="HTTPS GitHub release asset"):
        installer.validate_artifact("actionlint", spec, "linux-x64")


@pytest.mark.parametrize("sha256", ["", "0" * 63, "A" * 64, "g" * 64])
def test_checksum_must_be_pinned_lowercase_sha256(sha256):
    spec = specification(BINARY)
    spec["sha256"] = sha256
    with pytest.raises(ValueError, match="pinned SHA-256"):
        installer.validate_artifact("actionlint", spec, "linux-x64")


@pytest.mark.parametrize("archive_type", ["zip", "tar.gz"])
def test_traversing_archive_member_is_not_selected(archive_type):
    payload = zip_asset([("../actionlint", BINARY, stat.S_IFREG)]) if archive_type == "zip" else tar_asset([
        ("../actionlint", BINARY, tarfile.REGTYPE)])
    with pytest.raises(ValueError, match="one regular expected binary"):
        installer.binary_contents(payload, specification(payload, archive=archive_type))


@pytest.mark.parametrize("archive_type", ["zip", "tar.gz"])
def test_unselected_unsafe_paths_are_never_extracted(tmp_path, monkeypatch, archive_type):
    names = ["actionlint", "../escape", "/absolute/escape", "nested/not-installed"]
    payload = zip_asset([(name, BINARY, stat.S_IFREG) for name in names]) if archive_type == "zip" else tar_asset([
        (name, BINARY, tarfile.REGTYPE) for name in names])
    manifest(tmp_path, specification(payload, archive=archive_type))
    monkeypatch.setattr(installer, "download", lambda url: payload)
    destination = installer.install("actionlint", root=tmp_path, target="linux-x64")
    assert destination.read_bytes() == BINARY
    assert list(destination.parent.iterdir()) == [destination]
    assert not (tmp_path / "escape").exists()
    assert not (tmp_path / "artifacts" / "escape").exists()


@pytest.mark.parametrize("mode", [stat.S_IFLNK, stat.S_IFIFO, stat.S_IFCHR, stat.S_IFDIR])
def test_zip_binary_cannot_be_link_or_special_file(mode):
    payload = zip_asset([("actionlint", BINARY, mode)])
    with pytest.raises(ValueError, match="link or special file"):
        installer.binary_contents(payload, specification(payload, archive="zip"))


def test_zip_dos_directory_attribute_rejected():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        entry = zipfile.ZipInfo("actionlint")
        entry.external_attr = 0x10
        archive.writestr(entry, BINARY)
    payload = stream.getvalue()
    with pytest.raises(ValueError, match="must not be a directory"):
        installer.binary_contents(payload, specification(payload, archive="zip"))


def test_zip_nul_truncated_name_is_not_exact_expected_binary():
    payload = zip_asset([("actionlintXsuffix", BINARY, stat.S_IFREG)])
    payload = payload.replace(b"actionlintXsuffix", b"actionlint\x00suffix")
    with pytest.raises(ValueError, match="exact filename"):
        installer.binary_contents(payload, specification(payload, archive="zip"))


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.FIFOTYPE])
def test_tar_binary_cannot_be_link_or_special_file(kind):
    payload = tar_asset([("actionlint", b"", kind)])
    with pytest.raises(ValueError, match="one regular expected binary"):
        installer.binary_contents(payload, specification(payload, archive="tar.gz"))


@pytest.mark.parametrize("archive_type", ["zip", "tar.gz"])
def test_duplicate_expected_members_are_rejected(archive_type):
    if archive_type == "zip":
        with pytest.warns(UserWarning, match="Duplicate name"):
            payload = zip_asset([("actionlint", BINARY, stat.S_IFREG)] * 2)
    else:
        payload = tar_asset([("actionlint", BINARY, tarfile.REGTYPE)] * 2)
    with pytest.raises(ValueError, match="one regular expected binary"):
        installer.binary_contents(payload, specification(payload, archive=archive_type))


@pytest.mark.parametrize("payload", [b"", b"large"])
def test_binary_size_is_bounded_even_without_download(monkeypatch, payload):
    monkeypatch.setattr(installer, "MAX_BYTES", 4)
    with pytest.raises(ValueError, match="Empty or oversized binary"):
        installer.binary_contents(payload, specification(payload))


@pytest.mark.parametrize("archive_type", ["zip", "tar.gz"])
def test_oversized_archive_member_is_rejected_before_read(monkeypatch, archive_type):
    payload = zip_asset([("actionlint", BINARY, stat.S_IFREG)]) if archive_type == "zip" else tar_asset([
        ("actionlint", BINARY, tarfile.REGTYPE)])
    monkeypatch.setattr(installer, "MAX_BYTES", len(BINARY) - 1)
    with pytest.raises(ValueError, match="one regular expected binary"):
        installer.binary_contents(payload, specification(payload, archive=archive_type))


def test_checksum_error_does_not_replace_existing_installation(tmp_path, monkeypatch):
    destination = tmp_path / "artifacts" / "ci-tools" / "actionlint"
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"previous-verified-binary")
    manifest(tmp_path, specification(BINARY))
    monkeypatch.setattr(installer, "download", lambda url: b"tampered")
    with pytest.raises(ValueError, match="checksum mismatch"):
        installer.install("actionlint", root=tmp_path, target="linux-x64")
    assert destination.read_bytes() == b"previous-verified-binary"
    assert list(destination.parent.iterdir()) == [destination]


@pytest.mark.parametrize("failing_operation", ["chmod", "replace"])
def test_write_failure_preserves_existing_binary_and_removes_temporary_file(tmp_path, monkeypatch, failing_operation):
    destination = tmp_path / "artifacts" / "ci-tools" / "actionlint"
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"previous-verified-binary")
    manifest(tmp_path, specification(BINARY))
    monkeypatch.setattr(installer, "download", lambda url: BINARY)
    def failed(*args, **kwargs):
        raise OSError("simulated atomic installation failure")
    monkeypatch.setattr(installer.os, failing_operation, failed)
    with pytest.raises(OSError, match="simulated atomic installation failure"):
        installer.install("actionlint", root=tmp_path, target="linux-x64")
    assert destination.read_bytes() == b"previous-verified-binary"
    assert list(destination.parent.iterdir()) == [destination]


def test_existing_directory_symlink_cannot_escape_workspace(tmp_path, monkeypatch):
    root, outside = tmp_path / "workspace", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    manifest(root, specification(BINARY))
    try:
        (root / "artifacts").symlink_to(outside, target_is_directory=True)
    except OSError:
        # Windows may lack symlink privileges. Exercise the resolved-path guard
        # without privileges; Linux CI additionally traverses the real symlink.
        original = type(root).resolve
        def resolved(path, *args, **kwargs):
            if path == root / "artifacts" / "ci-tools":
                return outside / "ci-tools"
            return original(path, *args, **kwargs)
        monkeypatch.setattr(type(root), "resolve", resolved)
    monkeypatch.setattr(installer, "download", lambda url: BINARY)
    with pytest.raises(ValueError, match="within the workspace"):
        installer.install("actionlint", root=root, target="linux-x64")
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("version", [True, 2, "1", None])
def test_manifest_version_requires_integer_one(tmp_path, version):
    manifest(tmp_path, specification(BINARY), version=version)
    with pytest.raises(ValueError, match="manifest version"):
        installer.install("actionlint", root=tmp_path, target="linux-x64")
    assert not (tmp_path / "artifacts").exists()


@pytest.mark.parametrize("field", ["url", "sha256", "member", "archive"])
def test_malformed_artifact_fields_fail_cleanly_before_download(tmp_path, field):
    spec = specification(BINARY)
    spec[field] = None
    manifest(tmp_path, spec)
    with pytest.raises(ValueError, match="fields must be strings"):
        installer.install("actionlint", root=tmp_path, target="linux-x64")


class FakeResponse:
    def __init__(self, payload, url=RELEASE):
        self.payload = payload
        self.url = url
        self.limits = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit):
        self.limits.append(limit)
        return self.payload[:limit]


@pytest.mark.parametrize("payload", [b"", b"123456789"])
def test_download_size_limit_is_enforced_without_real_network(monkeypatch, payload):
    monkeypatch.setattr(installer, "MAX_BYTES", 8)
    response = FakeResponse(payload)
    monkeypatch.setattr(installer, "urlopen", lambda request, timeout: response)
    with pytest.raises(ValueError, match="Empty or oversized release asset"):
        installer.download(RELEASE)
    assert response.limits == [9]


def test_download_uses_bounded_read_and_rejects_non_https_redirect(monkeypatch):
    response = FakeResponse(BINARY)
    requests = []
    def opener(request, timeout):
        requests.append((request.full_url, timeout))
        return response
    monkeypatch.setattr(installer, "urlopen", opener)
    assert installer.download(RELEASE) == BINARY
    assert response.limits == [installer.MAX_BYTES + 1]
    assert requests == [(RELEASE, 60)]
    response.url = "http://github.com/insecure-redirect"
    with pytest.raises(ValueError, match="redirect must remain HTTPS"):
        installer.download(RELEASE)
    assert response.limits == [installer.MAX_BYTES + 1]
