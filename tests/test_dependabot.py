"""Dependabot checks reject ambiguous configuration and preserve valid extensions."""
from __future__ import annotations

from copy import deepcopy
import pytest

from tools.check_dependabot import ConfigError, MAX_BYTES, ROOT, check, main, parse, validate


def config():
    return {
        "version": 2,
        "updates": [{
            "package-ecosystem": "pip", "directory": "/",
            "schedule": {"interval": "weekly", "day": "monday", "time": "06:00", "timezone": "Europe/Berlin"},
            "open-pull-requests-limit": 2,
            "groups": {"python-dependencies": {"patterns": ["*"], "update-types": ["minor", "patch"]}},
        }],
    }


def test_repository_configuration_covers_all_manifests():
    path = ROOT / ".github" / "dependabot.yml"
    assert check(path) == 4
    actual = parse(path.read_text(encoding="utf-8"))
    assert {item["package-ecosystem"] for item in actual["updates"]} == {"pip", "docker", "github-actions", "npm"}
    assert all(item["directory"] == "/" for item in actual["updates"])


@pytest.mark.parametrize("raw", [
    "version: 2\nversion: 2\nupdates: []\n",
    "version: 2\nupdates:\n- package-ecosystem: pip\n  schedule:\n    interval: daily\n    interval: weekly\n",
    "defaults: &defaults {directory: /}\nupdate:\n  <<: *defaults\n  <<: *defaults\n",
])
def test_duplicate_yaml_keys_are_rejected(raw):
    with pytest.raises(ConfigError, match="duplicate mapping key"):
        parse(raw)


def test_yaml_merge_override_remains_valid():
    actual = parse("""version: 2
defaults: &defaults
  directory: /old
  schedule: {interval: daily}
updates:
  - <<: *defaults
    package-ecosystem: pip
    directory: /
""")
    assert validate(actual) == 1
    assert actual["updates"][0]["directory"] == "/"


@pytest.mark.parametrize("raw", [
    "!!python/object/apply:os.system ['echo unsafe']",
    "version: [unclosed",
    "version: 2\nupdates: &cycle [*cycle]",
    "version: 2\nupdates: []\n? [invalid, key]\n: value",
])
def test_unsafe_malformed_or_cyclic_yaml_has_clean_errors(raw):
    with pytest.raises(ConfigError):
        parse(raw)


@pytest.mark.parametrize("version", [1, 3, "2", True, None])
def test_version_must_be_integer_two(version):
    actual = config()
    actual["version"] = version
    with pytest.raises(ConfigError, match="version"):
        validate(actual)


@pytest.mark.parametrize("updates", [None, [], {}, ["pip"]])
def test_updates_have_required_structure(updates):
    actual = config()
    actual["updates"] = updates
    with pytest.raises(ConfigError):
        validate(actual)


@pytest.mark.parametrize("field,value", [
    ("package-ecosystem", "github-action"),
    ("directory", ".github/workflows"),
    ("directory", "/../other"),
    ("directory", "/a/./b"),
    ("directory", "//network/share"),
    ("directory", "/a\\b"),
    ("directory", "/packages/*"),
    ("directory", "/a\nb"),
    ("open-pull-requests-limit", -1),
    ("open-pull-requests-limit", True),
    ("open-pull-requests-limit", "2"),
    ("target-branch", ""),
])
def test_invalid_update_options(field, value):
    actual = config()
    actual["updates"][0][field] = value
    with pytest.raises(ConfigError):
        validate(actual)


def test_directory_and_directories_are_mutually_exclusive():
    actual = config()
    actual["updates"][0]["directories"] = ["/"]
    with pytest.raises(ConfigError, match="exactly one"):
        validate(actual)
    del actual["updates"][0]["directory"]
    del actual["updates"][0]["directories"]
    with pytest.raises(ConfigError, match="exactly one"):
        validate(actual)


def test_github_actions_requires_root_directory():
    actual = config()
    actual["updates"][0].update({"package-ecosystem": "github-actions", "directory": "/.github/workflows"})
    with pytest.raises(ConfigError, match="GitHub Actions directory"):
        validate(actual)


def test_duplicate_directory_rejected_but_distinct_target_branch_allowed():
    actual = config()
    actual["updates"].append(deepcopy(actual["updates"][0]))
    with pytest.raises(ConfigError, match="duplicate ecosystem"):
        validate(actual)
    actual["updates"][1]["target-branch"] = "release/1"
    assert validate(actual) == 2


@pytest.mark.parametrize("field,value", [
    ("interval", "hourly"), ("day", "Mondays"), ("time", "24:00"),
    ("time", "06:60"), ("time", "6:00"), ("time", 600),
    ("timezone", "Europe/Unknown"), ("timezone", "../Europe/Berlin"),
])
def test_invalid_schedule_options(field, value):
    actual = config()
    actual["updates"][0]["schedule"][field] = value
    with pytest.raises(ConfigError):
        validate(actual)


@pytest.mark.parametrize("interval", ["daily", "weekly", "monthly", "quarterly", "semiannually", "yearly"])
def test_documented_schedule_intervals_allowed(interval):
    actual = config()
    actual["updates"][0]["schedule"] = {"interval": interval}
    assert validate(actual) == 1


@pytest.mark.parametrize("expression", ["0 9 * * *", "every day at 5pm"])
def test_cron_accepts_both_github_expression_formats(expression):
    actual = config()
    actual["updates"][0]["schedule"] = {"interval": "cron", "cronjob": expression}
    assert validate(actual) == 1


def test_cron_requires_expression_and_matching_interval():
    actual = config()
    actual["updates"][0]["schedule"] = {"interval": "cron"}
    with pytest.raises(ConfigError, match="cronjob"):
        validate(actual)
    actual["updates"][0]["schedule"] = {"interval": "weekly", "cronjob": "0 9 * * *"}
    with pytest.raises(ConfigError, match="requires interval cron"):
        validate(actual)


@pytest.mark.parametrize("field,value", [
    ("patterns", "*"), ("patterns", [None]), ("update-types", ["security"]),
    ("applies-to", "security"), ("dependency-type", "indirect"), ("group-by", "directory"),
])
def test_invalid_group_rules(field, value):
    actual = config()
    actual["updates"][0]["groups"]["python-dependencies"][field] = value
    with pytest.raises(ConfigError):
        validate(actual)


def test_additional_github_options_and_glob_directories_are_preserved():
    actual = config()
    actual["registries"] = {"internal": {"type": "python-index", "url": "https://packages.example.invalid"}}
    entry = actual["updates"][0]
    del entry["directory"]
    entry.update({"directories": ["/services/*", "/tools"], "registries": ["internal"], "labels": [],
                  "cooldown": {"default-days": 3}, "open-pull-requests-limit": 0})
    entry["groups"]["python-dependencies"].update({"applies-to": "security-updates", "exclude-patterns": ["internal-*"],
                                                 "dependency-type": "development", "group-by": "dependency-name"})
    assert validate(actual) == 1


def test_multi_ecosystem_schedule_inheritance():
    actual = {"version": 2, "multi-ecosystem-groups": {"infrastructure": {"schedule": {"interval": "weekly"}}},
              "updates": [{"package-ecosystem": "docker", "directory": "/", "patterns": ["nginx"],
                           "multi-ecosystem-group": "infrastructure"},
                          {"package-ecosystem": "terraform", "directory": "/", "patterns": ["aws"],
                           "multi-ecosystem-group": "infrastructure"}]}
    assert validate(actual) == 2
    actual["updates"][1]["multi-ecosystem-group"] = "missing"
    with pytest.raises(ConfigError, match="not defined"):
        validate(actual)


def test_schedule_required_without_inheritance():
    actual = config()
    del actual["updates"][0]["schedule"]
    with pytest.raises(ConfigError, match="required unless inherited"):
        validate(actual)


def test_file_size_and_utf8_limits(tmp_path):
    path = tmp_path / "dependabot.yml"
    path.write_bytes(b"x" * (MAX_BYTES + 1))
    with pytest.raises(ConfigError, match="size limit"):
        check(path)
    path.write_bytes(b"\xff")
    with pytest.raises(ConfigError, match="UTF-8"):
        check(path)


def test_cli_errors_do_not_echo_yaml_values(tmp_path, capsys):
    path = tmp_path / "dependabot.yml"
    sentinel = "private-registry-password-sentinel"
    path.write_text(f"version: [{sentinel}", encoding="utf-8")
    assert main([str(path)]) == 1
    result = capsys.readouterr()
    assert sentinel not in result.err
    assert "invalid or unsupported YAML" in result.err
    assert main([str(tmp_path / "missing.yml")]) == 1


def test_cli_success(capsys):
    assert main([]) == 0
    assert "4 update entries" in capsys.readouterr().out
