#!/usr/bin/env python3
"""Update every pinned dependency to its latest release.

Covers:
  - Python packages      -> uv lock --upgrade (respects the ranges in pyproject.toml)
  - Playwright           -> pyproject.toml pin + Dockerfile base image + .env.example
  - radare2, JADX, Detect-It-Easy, Temurin JRE -> Dockerfile ARG pins

Usage:
  python scripts/update_deps.py            # apply updates
  python scripts/update_deps.py --check    # only report what is outdated
  python scripts/update_deps.py --no-python  # skip uv lock

Afterwards: run the tests, then `docker compose build --pull && docker compose up -d`.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCKERFILE = ROOT / "Dockerfile"
PYPROJECT = ROOT / "pyproject.toml"
ENV_EXAMPLE = ROOT / ".env.example"
GITHUB = "https://api.github.com/repos/{repo}/releases?per_page=30"


def _get_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "hunting-bad-guys-updater"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def _releases(repo: str) -> list[dict]:
    return [r for r in _get_json(GITHUB.format(repo=repo)) if not r.get("draft")]


def _version_key(v: str) -> tuple:
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.+_-]", v))


# ── Latest version lookups ────────────────────────────────────────────────────


def latest_playwright() -> str | None:
    """Newest Playwright on PyPI that also has a Docker image tag."""
    pypi = _get_json("https://pypi.org/pypi/playwright/json")["releases"]
    tags = set(_get_json("https://mcr.microsoft.com/v2/playwright/python/tags/list")["tags"])
    stable = [v for v in pypi if re.fullmatch(r"\d+\.\d+\.\d+", v) and f"v{v}-noble" in tags]
    return max(stable, key=_version_key) if stable else None


def latest_radare2() -> str | None:
    for r in _releases("radareorg/radare2"):
        if r["prerelease"]:
            continue
        names = {a["name"] for a in r["assets"]}
        tag = r["tag_name"].lstrip("v")
        if f"radare2_{tag}_amd64.deb" in names and f"radare2-dev_{tag}_amd64.deb" in names:
            return tag
    return None


def latest_jadx() -> str | None:
    for r in _releases("skylot/jadx"):
        if not r["prerelease"]:
            return r["tag_name"].lstrip("v")
    return None


def latest_die() -> str | None:
    for r in _releases("horsicq/DIE-engine"):
        if r["prerelease"]:
            continue
        tag = r["tag_name"]
        if any(a["name"] == f"die_{tag}_Ubuntu_24.04_amd64.deb" for a in r["assets"]):
            return tag
    return None


def latest_temurin() -> str | None:
    data = _get_json(
        "https://api.adoptium.net/v3/assets/latest/17/hotspot"
        "?architecture=x64&image_type=jre&os=linux&vendor=eclipse"
    )
    return data[0]["release_name"].removeprefix("jdk-") if data else None


# ── Pin rewriting ─────────────────────────────────────────────────────────────


def current_arg(name: str) -> str:
    m = re.search(rf"^ARG {name}=(.+)$", DOCKERFILE.read_text(encoding="utf-8"), re.M)
    if not m:
        sys.exit(f"ARG {name} not found in Dockerfile")
    return m.group(1).strip()


def set_arg(name: str, value: str) -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    DOCKERFILE.write_text(
        re.sub(rf"^ARG {name}=.+$", f"ARG {name}={value}", text, flags=re.M), encoding="utf-8"
    )


def set_playwright(version: str) -> None:
    set_arg("PLAYWRIGHT_VERSION", version)
    text = PYPROJECT.read_text(encoding="utf-8")
    PYPROJECT.write_text(
        re.sub(r'"playwright==[\d.]+"', f'"playwright=={version}"', text), encoding="utf-8"
    )
    if ENV_EXAMPLE.exists():
        text = ENV_EXAMPLE.read_text(encoding="utf-8")
        ENV_EXAMPLE.write_text(
            re.sub(r"^PLAYWRIGHT_VERSION=.+$", f"PLAYWRIGHT_VERSION={version}", text, flags=re.M),
            encoding="utf-8",
        )


PINS = [
    # (label, Dockerfile ARG, lookup, apply)
    ("Playwright", "PLAYWRIGHT_VERSION", latest_playwright, set_playwright),
    ("radare2", "RADARE2_VERSION", latest_radare2, lambda v: set_arg("RADARE2_VERSION", v)),
    ("JADX", "JADX_VERSION", latest_jadx, lambda v: set_arg("JADX_VERSION", v)),
    ("Detect-It-Easy", "DIE_VERSION", latest_die, lambda v: set_arg("DIE_VERSION", v)),
    ("Temurin JRE 17", "TEMURIN_VERSION", latest_temurin, lambda v: set_arg("TEMURIN_VERSION", v)),
]


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--check", action="store_true", help="report only, change nothing")
    parser.add_argument("--no-python", action="store_true", help="skip uv lock --upgrade")
    args = parser.parse_args()

    changed = 0
    print("Tool pins (Dockerfile):")
    for label, arg, lookup, apply in PINS:
        current = current_arg(arg)
        try:
            latest = lookup()
        except Exception as exc:
            print(f"  {label:<16} {current:<12} lookup failed: {exc}")
            continue
        if not latest or _version_key(latest) <= _version_key(current):
            print(f"  {label:<16} {current:<12} up to date")
            continue
        print(f"  {label:<16} {current:<12} -> {latest}")
        changed += 1
        if not args.check:
            apply(latest)

    if not args.no_python:
        print("\nPython packages (uv.lock):")
        cmd = ["uv", "lock", "--upgrade"] + (["--dry-run"] if args.check else [])
        try:
            subprocess.run(cmd, cwd=ROOT, check=True)
        except FileNotFoundError:
            print("  uv is not installed: https://docs.astral.sh/uv/getting-started/installation/")
            return 1

    if args.check:
        print(f"\n{changed} tool pin(s) outdated. Run without --check to apply.")
    else:
        print("\nDone. Next steps:")
        print("  uv sync && uv run pytest")
        print("  docker compose build --pull && docker compose up -d")
    return 0


if __name__ == "__main__":
    sys.exit(main())
