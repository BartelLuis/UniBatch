"""Lint safe YAML and the documented core of Dependabot v2 configuration.

This is not a replacement for GitHub's complete configuration validator. Additional
GitHub options are allowed, including private registries and newer optional keys.
Reference: https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference
"""
from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import re
import sys
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml


ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 1_048_576
# Documented ecosystem names, checked against GitHub's reference on 2026-10-03.
ECOSYSTEMS = frozenset({
    "bazel", "bun", "bundler", "cargo", "composer", "conda", "deno", "devcontainers",
    "docker", "docker-compose", "dotnet-sdk", "helm", "mix", "julia", "elm", "gitsubmodule",
    "github-actions", "gomod", "gradle", "maven", "nix", "npm", "nuget", "opentofu", "pip",
    "pre-commit", "pub", "rust-toolchain", "sbt", "swift", "terraform", "uv", "vcpkg",
})
INTERVALS = frozenset({"daily", "weekly", "monthly", "quarterly", "semiannually", "yearly", "cron"})
DAYS = frozenset({"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"})
TIME = re.compile(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]")
GROUP_NAME = re.compile(r"[A-Za-z](?:[A-Za-z0-9_|-]*[A-Za-z])?")


class ConfigError(ValueError):
    """A configuration problem that can be displayed without scalar values."""


class UniqueKeySafeLoader(yaml.SafeLoader):
    """Keep safe constructors and reject repeated explicit mapping keys.

    YAML merge defaults may legitimately be overridden by an explicit key, so
    duplicate detection happens before SafeLoader flattens the merged mappings.
    """

    def construct_mapping(self, node, deep=False):
        keys = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                key = "<<"
            else:
                key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise ConfigError(f"line {key_node.start_mark.line + 1}: mapping keys must be strings")
            if key in keys:
                raise ConfigError(f"line {key_node.start_mark.line + 1}: duplicate mapping key")
            keys.add(key)
        return super().construct_mapping(node, deep=deep)


def mapping(value, where):
    if not isinstance(value, dict):
        raise ConfigError(f"{where}: expected a mapping")
    return value


def text(value, where):
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{where}: expected a non-empty string")
    return value


def strings(value, where):
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{where}: expected a non-empty list of strings")
    for index, item in enumerate(value):
        text(item, f"{where}[{index}]")
    return value


def choice(value, choices, where):
    if not isinstance(value, str) or value not in choices:
        raise ConfigError(f"{where}: unsupported value")


def check_graph(value, active=None, seen=None, depth=0):
    """Reject cyclic aliases; avoid repeated traversal of shared YAML aliases."""
    if active is None:
        active, seen = set(), set()
    if depth > 64:
        raise ConfigError("YAML nesting exceeds 64 levels")
    if not isinstance(value, (dict, list)):
        return
    identity = id(value)
    if identity in active:
        raise ConfigError("YAML aliases must not form a cycle")
    if identity in seen:
        return
    active.add(identity)
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ConfigError("YAML mapping keys must be strings")
        children = value.values()
    else:
        children = value
    for child in children:
        check_graph(child, active, seen, depth + 1)
    active.remove(identity)
    seen.add(identity)


def parse(raw: str):
    try:
        loader = UniqueKeySafeLoader(raw)
        try:
            result = loader.get_single_data()
        finally:
            loader.dispose()
        check_graph(result)
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        location = f" at line {mark.line + 1}" if mark is not None else ""
        # PyYAML's original error embeds source lines, including registry secrets.
        raise ConfigError(f"invalid or unsupported YAML{location}") from None
    except RecursionError:
        raise ConfigError("YAML nesting is too deep") from None
    return result


def schedule(value, where):
    value = mapping(value, where)
    interval = value.get("interval")
    choice(interval, INTERVALS, f"{where}.interval")
    if "day" in value:
        choice(value["day"], DAYS, f"{where}.day")
    if "time" in value and (not isinstance(value["time"], str) or not TIME.fullmatch(value["time"])):
        raise ConfigError(f"{where}.time: expected a quoted 24-hour hh:mm value")
    if "timezone" in value:
        timezone = text(value["timezone"], f"{where}.timezone")
        try:
            ZoneInfo(timezone)
        except (ZoneInfoNotFoundError, ValueError):
            raise ConfigError(f"{where}.timezone: expected an installed IANA timezone identifier") from None
    if interval == "cron":
        # GitHub accepts both five-field cron and natural expressions. Let GitHub
        # interpret its expression grammar rather than rejecting valid extensions.
        text(value.get("cronjob"), f"{where}.cronjob")
    elif "cronjob" in value:
        raise ConfigError(f"{where}.cronjob: requires interval cron")


def groups(value, where):
    for index, (name, rule) in enumerate(mapping(value, where).items()):
        rule_where = f"{where}[{index}]"
        if not GROUP_NAME.fullmatch(name):
            raise ConfigError(f"{rule_where}: invalid group identifier")
        rule = mapping(rule, rule_where)
        for field in ("patterns", "exclude-patterns"):
            if field in rule:
                strings(rule[field], f"{rule_where}.{field}")
        for field, options in (
            ("applies-to", {"version-updates", "security-updates"}),
            ("dependency-type", {"production", "development"}),
            ("group-by", {"dependency-name"}),
        ):
            if field in rule:
                choice(rule[field], options, f"{rule_where}.{field}")
        if "update-types" in rule:
            for item in strings(rule["update-types"], f"{rule_where}.update-types"):
                choice(item, {"major", "minor", "patch"}, f"{rule_where}.update-types")


def directory(value, where, *, allow_glob):
    value = text(value, where)
    if not value.startswith("/") or value.startswith("//") or "\\" in value:
        raise ConfigError(f"{where}: expected a repository-root-relative POSIX path")
    if any(part in {".", ".."} for part in value.split("/")):
        raise ConfigError(f"{where}: directory traversal is not allowed")
    if any(ord(character) < 32 for character in value):
        raise ConfigError(f"{where}: control characters are not allowed")
    if not allow_glob and any(character in value for character in "*?["):
        raise ConfigError(f"{where}: glob patterns require directories, not directory")
    return str(PurePosixPath(value))


def validate(config):
    """Validate documented core options; return the number of update entries."""
    config = mapping(config, "configuration")
    if type(config.get("version")) is not int or config["version"] != 2:
        raise ConfigError("version: expected integer 2")
    updates = config.get("updates")
    if not isinstance(updates, list) or not updates:
        raise ConfigError("updates: expected a non-empty list")
    multi_groups = mapping(config.get("multi-ecosystem-groups", {}), "multi-ecosystem-groups")
    for index, rule in enumerate(multi_groups.values()):
        rule_where = f"multi-ecosystem-groups[{index}]"
        rule = mapping(rule, rule_where)
        schedule(rule.get("schedule"), f"{rule_where}.schedule")
    roots = set()
    for index, update in enumerate(updates):
        where = f"updates[{index}]"
        update = mapping(update, where)
        ecosystem = update.get("package-ecosystem")
        choice(ecosystem, ECOSYSTEMS, f"{where}.package-ecosystem")
        if ("directory" in update) == ("directories" in update):
            raise ConfigError(f"{where}: define exactly one of directory or directories")
        paths = [update["directory"]] if "directory" in update else strings(update["directories"], f"{where}.directories")
        branch = text(update["target-branch"], f"{where}.target-branch") if "target-branch" in update else None
        for path_index, path in enumerate(paths):
            path = directory(path, f"{where}.directories[{path_index}]", allow_glob="directories" in update)
            if ecosystem == "github-actions" and path != "/":
                raise ConfigError(f"{where}: GitHub Actions directory must be /")
            key = (ecosystem, branch, path)
            if key in roots:
                raise ConfigError(f"{where}: duplicate ecosystem, target branch and directory")
            roots.add(key)
        if "multi-ecosystem-group" in update:
            group = text(update["multi-ecosystem-group"], f"{where}.multi-ecosystem-group")
            if group not in multi_groups:
                raise ConfigError(f"{where}.multi-ecosystem-group: group is not defined")
        if "schedule" in update:
            schedule(update["schedule"], f"{where}.schedule")
        elif "multi-ecosystem-group" not in update:
            raise ConfigError(f"{where}.schedule: required unless inherited from a multi-ecosystem group")
        if "open-pull-requests-limit" in update:
            limit = update["open-pull-requests-limit"]
            if type(limit) is not int or limit < 0:
                raise ConfigError(f"{where}.open-pull-requests-limit: expected a non-negative integer")
        if "groups" in update:
            groups(update["groups"], f"{where}.groups")
    return len(updates)


def check(path: Path = ROOT / ".github" / "dependabot.yml"):
    with path.open("rb") as source:
        raw = source.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ConfigError("configuration exceeds the 1 MiB size limit")
    try:
        decoded = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ConfigError("configuration must use UTF-8") from None
    return validate(parse(decoded))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path, default=ROOT / ".github" / "dependabot.yml")
    args = parser.parse_args(argv)
    try:
        count = check(args.path)
    except (OSError, ConfigError) as error:
        print(f"Dependabot lint failed: {error}", file=sys.stderr)
        return 1
    print(f"Dependabot YAML and core v2 options are valid for {count} update entries; GitHub validates additional options.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
