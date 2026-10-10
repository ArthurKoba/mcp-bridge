#!/usr/bin/env python3
"""Sync x-watch-path-coolify from one Git Compose into one verified Coolify Application.

No persistent state, no secrets on stdout, no implicit deploy. Dry-run by default.
Runtime API secrets must be passed through COOLIFY_API_TOKEN, never command arguments.
Run only after owner-approved Git publication and Coolify app creation.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

ALLOWED_PATH = re.compile(r"!?[a-zA-Z0-9][a-zA-Z0-9_./*?-]*\Z")
WATCH_HEADER = re.compile(r"^x-watch-path-coolify:\s*$", re.MULTILINE)


class SyncError(Exception):
    pass


def read_watch_paths(path: Path) -> list[str]:
    """Require our constrained YAML form: x-watch-path-coolify: followed by JSON-quoted lines."""
    source = path.read_text(encoding="utf-8")
    matches = list(WATCH_HEADER.finditer(source))
    if len(matches) != 1 or matches[0].start() != 0:
        raise SyncError("exactly one top-level x-watch-path-coolify is required")
    lines = source[matches[0].end():].splitlines()
    paths: list[str] = []
    for line in lines:
        if not line.strip():
            if paths:
                break
            continue
        if not line.startswith("  - "):
            break
        try:
            item = json.loads(line[4:])
        except json.JSONDecodeError as exc:
            raise SyncError("watch path list needs JSON-quoted scalar items") from exc
        if (
            not isinstance(item, str)
            or not ALLOWED_PATH.fullmatch(item)
            or item.startswith(("!", "/"))
            or ".." in item.split("/")
            or len(item) > 255
        ):
            raise SyncError("invalid watch path value")
        if item in paths:
            raise SyncError("duplicate watch path")
        paths.append(item)
    if not paths or len(paths) > 100:
        raise SyncError("watch paths missing or excessive")
    return paths


def request_json(base: str, token: str, method: str, route: str, payload: dict | None = None) -> dict:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = Request(f"{base.rstrip('/')}/api/v1/{route}", data=body, headers=headers, method=method)
    try:
        with urlopen(req, timeout=15) as response:
            data = json.load(response)
    except HTTPError as exc:
        raise SyncError(f"Coolify returned HTTP {exc.code} for {route}") from None
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise SyncError(f"Coolify request failed for {route}: {type(exc).__name__}") from None
    if not isinstance(data, dict):
        raise SyncError("unexpected Coolify application response")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose", required=True, type=Path, help="one staged/Git coolify Compose file")
    parser.add_argument("--application-uuid", required=True)
    parser.add_argument("--branch", required=True, help="expected published DEV Git branch")
    parser.add_argument("--coolify-url", required=True, help="trusted Coolify instance HTTPS URL")
    parser.add_argument("--apply", action="store_true", help="write only watch_paths; default read-only")
    args = parser.parse_args()

    # Do not allow publication automation to redirect a bearer into a URL with userinfo.
    url = urlsplit(args.coolify_url)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment or url.path.rstrip("/"):
        raise SyncError("Coolify URL must be a bare trusted HTTPS origin")
    if not re.fullmatch(r"[a-z0-9]{24}", args.application_uuid):
        raise SyncError("expected a 24-character Coolify Application resource identifier")
    paths = read_watch_paths(args.compose)
    print(f"Desired watch paths: {len(paths)} from {args.compose}")

    token = os.environ.get("COOLIFY_API_TOKEN", "")
    if not token:
        print("DRY RUN: no COOLIFY_API_TOKEN; no remote state checked or changed")
        return 0 if not args.apply else 2
    current = request_json(args.coolify_url, token, "GET", f"applications/{args.application_uuid}")
    if current.get("git_repository", "").casefold() != "arthurkoba/briareus":
        raise SyncError("unexpected Git repository; refusing update")
    if current.get("git_branch") != args.branch:
        raise SyncError("unexpected published Git branch; refusing update")
    service = args.compose.parent.name
    if current.get("base_directory") != f"/deploy/{service}":
        raise SyncError("unexpected Base directory; refusing update")
    if current.get("build_pack") != "dockercompose":
        raise SyncError("target is not a Git-backed Docker Compose Application")
    value = "\n".join(paths)
    if current.get("watch_paths") == value:
        print("ALREADY SYNCHRONIZED: no change")
        return 0
    if not args.apply:
        print("DRY RUN: target matched; Coolify watch_paths differ; use --apply after approval")
        return 0
    request_json(args.coolify_url, token, "PATCH", f"applications/{args.application_uuid}", {"watch_paths": value})
    verified = request_json(args.coolify_url, token, "GET", f"applications/{args.application_uuid}")
    if verified.get("watch_paths") != value:
        raise SyncError("Coolify did not persist exact watch_paths; disable auto-deploy")
    print("SYNCHRONIZED: watch_paths applied and verified")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SyncError, ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
