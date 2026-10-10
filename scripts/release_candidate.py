"""Immutable full-wheel Briareus SOURCE release producer (PACKAGING-V1).

Stage ONLY central locally ACCEPTED first-party source plus Backend-owned
review changes. Never copy stale Runtime/Frontend files from an active worker
checkout, edit other owners, inspect secrets, commit or publish Git.

Provenance is a source-reviewable candidate until a reviewer publishes an
immutable Git tree and D4 proves artifact transfer/pinning.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import cast

_VERSION_BASE = "0.1.0"
_PROVENANCE = "services/common/release_provenance.json"
_ROOT_INPUTS = ("pyproject.toml", "uv.lock", "README.md", "LICENSE", ".python-version")
_PACKAGE_DIRS = ("services", "scripts")
_EXCLUDE_PARTS = frozenset(
    {
        "__pycache__",
        "node_modules",
        ".venv",
        ".mypy_cache",
        ".ruff_cache",
        "dist",
        "build",
        ".git",
        "local",
        "artifacts",
        "secrets",
    }
)
_EXCLUDE_SUFFIXES = (".pyc", ".pyo", ".pem", ".key", ".p12")
_SCHEMA = "briareus-full-wheel-source-v1"


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _normalize_root(path: str, raw: bytes) -> bytes:
    if path == "pyproject.toml":
        text = raw.decode("utf-8")
        match = re.search(r'(?m)^version = "[^"]+"$', text)
        if match is None:
            raise ValueError("missing static project distribution version")
        return (
            text[: match.start()] + 'version = "<REVIEWED_RELEASE_VERSION>"' + text[match.end() :]
        ).encode()
    if path == "uv.lock":
        text = raw.decode("utf-8")
        pattern = r'(?m)(^\[\[package\]\]\nname = "briareus"\nversion = ")[^"]+(")'
        text, replacements = re.subn(
            pattern,
            r"\g<1><REVIEWED_RELEASE_VERSION>\2",
            text,
        )
        if replacements != 1:
            raise ValueError("uv.lock must contain one canonical briareus package")
        return text.encode()
    return raw


def _manifest_inputs(root: Path) -> list[dict[str, object]]:
    found: set[str] = set(_ROOT_INPUTS)
    for dirname in _PACKAGE_DIRS:
        base = root / dirname
        if not base.is_dir():
            raise ValueError(f"canonical first-party source directory missing: {dirname}")
        for file in base.rglob("*"):
            if not file.is_file():
                continue
            relative = file.relative_to(root).as_posix()
            if (
                relative == _PROVENANCE
                or any(part in _EXCLUDE_PARTS for part in file.relative_to(root).parts)
                or file.name.startswith(".env")
                or file.suffix in _EXCLUDE_SUFFIXES
                or file.is_symlink()
            ):
                continue
            found.add(relative)
    entries: list[dict[str, object]] = []
    for relative in sorted(found):
        file = root / relative
        if not file.is_file() or file.is_symlink():
            raise ValueError(f"release source input missing or symlinked: {relative}")
        raw = _normalize_root(relative, file.read_bytes())
        entries.append({"path": relative, "sha256": _digest(raw), "bytes": len(raw)})
    return entries


def _source_digest(entries: list[dict[str, object]]) -> str:
    return _digest(
        json.dumps(
            entries,
            separators=(",", ":"),
            sort_keys=True,
            ensure_ascii=True,
        ).encode()
    )


def _run_capture(command: list[str], cwd: Path) -> str:
    r = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=True)
    return r.stdout.strip()


def _json_write(path: Path, content: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            content,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _manifest(
    root: Path,
    *,
    git_base_commit: str,
    git_base_tree: str,
) -> dict[str, object]:
    if not re.fullmatch(r"[0-9a-f]{40}", git_base_commit) or not re.fullmatch(
        r"[0-9a-f]{40}",
        git_base_tree,
    ):
        raise ValueError("Git source identifiers must be exact verified SHA-1")
    entries = _manifest_inputs(root)
    content = _source_digest(entries)
    return {
        "schema": _SCHEMA,
        "name": "briareus",
        "version": f"{_VERSION_BASE}+a13.s{content[:16]}",
        "source_input_sha256": content,
        "source_input_files": entries,
        "base_git_commit": git_base_commit,
        "base_git_tree": git_base_tree,
        # The repository has uncommitted, independently reviewed source
        # integrations. Do NOT claim a published/reviewed final tree from
        # an old base commit. Orchestrator will attach the final tree on pin.
        "published_git_tree": None,
        "review_state": "UNPUBLISHED_SOURCE_CANDIDATE",
        "python_abi": "cp313",
        "wheel_tag": "py3-none-any",
        "owner_alembic": {
            "identity": "identity_0002",
            "access": "access_0001",
            "platform": "platform_0003",
            "resources": "resources_0002",
            "files": "files_0002",
            "runtime": "runtime_0003",
            "reverse": "reverse_0002",
            "ingest": "ingest_0001",
        },
    }


def _set_version(root: Path, version: str) -> None:
    path = root / "pyproject.toml"
    content = path.read_text(encoding="utf-8")
    content, n = re.subn(
        r'(?m)^version = "[^"]+"$',
        f'version = "{version}"',
        content,
        count=1,
    )
    if n != 1:
        raise ValueError("canonical project version could not be changed safely")
    path.write_text(content, encoding="utf-8")


def freeze(
    root: Path,
    *,
    git_base_commit: str,
    git_base_tree: str,
) -> dict[str, object]:
    outcome = _manifest(
        root,
        git_base_commit=git_base_commit,
        git_base_tree=git_base_tree,
    )
    _set_version(root, str(outcome["version"]))
    _json_write(root / _PROVENANCE, outcome)
    # Changing embedded version/provenance must not change the canonical
    # root-independent source digest.
    if _manifest_inputs(root) != outcome["source_input_files"]:
        raise ValueError("release version freeze caused a source input digest cycle")
    return outcome


def verify(root: Path) -> dict[str, object]:
    existing = json.loads((root / _PROVENANCE).read_text(encoding="utf-8"))
    if existing.get("schema") != _SCHEMA or existing.get("name") != "briareus":
        raise ValueError("wrong installed Briareus source manifest format")
    expected = _manifest(
        root,
        git_base_commit=existing["base_git_commit"],
        git_base_tree=existing["base_git_tree"],
    )
    if existing != expected:
        raise ValueError("release source bytes changed without unique new release version")
    if f'version = "{existing["version"]}"' not in (root / "pyproject.toml").read_text(
        encoding="utf-8"
    ):
        raise ValueError("pyproject.toml version not equal to frozen manifest")
    return expected


def _accepted_backend_delta(worker: Path, coordination: Path) -> list[str]:
    r = subprocess.run(
        ["python", str(coordination / "agent_sync.py"), "status", "backend"],
        cwd=worker,
        capture_output=True,
        text=True,
        check=True,
    )
    report = json.loads(r.stdout)
    if report.get("conflicts"):
        raise ValueError("owner source report has unresolved ownership conflicts")
    return list(report["paths"])


def stage(
    worker: Path,
    *,
    central: Path,
    coordination: Path,
    destination: Path,
) -> list[str]:
    if destination.exists():
        raise FileExistsError("immutable release candidate staging path already exists")
    if not (central / "AGENTS.md").is_file():
        raise ValueError("central locally reviewed source checkout unavailable")
    destination.mkdir(parents=True)
    for filename in _ROOT_INPUTS:
        shutil.copy2(central / filename, destination / filename)
    for dirname in _PACKAGE_DIRS:
        shutil.copytree(
            central / dirname,
            destination / dirname,
            ignore=shutil.ignore_patterns(
                "__pycache__",
                "*.pyc",
                ".mypy_cache",
                ".ruff_cache",
                "node_modules",
                "dist",
                "build",
            ),
        )
    changed = _accepted_backend_delta(worker, coordination)
    allowed = (
        "services/common/",
        "services/identity/",
        "services/authorization/",
        "services/teams/",
        "services/projects/",
        "services/agents/",
        "services/admin-api/src/",
        "scripts/",
    )
    for relative in changed:
        if relative not in {
            "pyproject.toml",
            "uv.lock",
            ".env.example",
        } and not relative.startswith(allowed):
            raise ValueError(f"attempted to overlay non-Backend owner path: {relative}")
        original = worker / relative
        target = destination / relative
        if original.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(original, target)
        elif target.exists():
            target.unlink()
    return changed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    freeze_cmd = actions.add_parser("freeze")
    freeze_cmd.add_argument("--root", type=Path, required=True)
    freeze_cmd.add_argument("--git-base-commit", required=True)
    freeze_cmd.add_argument("--git-base-tree", required=True)
    verify_cmd = actions.add_parser("verify")
    verify_cmd.add_argument("--root", type=Path, required=True)
    stage_cmd = actions.add_parser("stage")
    for item in ("worker", "central", "coordination", "destination"):
        stage_cmd.add_argument(f"--{item}", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "freeze":
        result = freeze(
            args.root.resolve(),
            git_base_commit=args.git_base_commit,
            git_base_tree=args.git_base_tree,
        )
        print(
            json.dumps(
                {
                    "version": result["version"],
                    "source_input_sha256": result["source_input_sha256"],
                    "files": len(cast(list[dict[str, object]], result["source_input_files"])),
                },
                sort_keys=True,
            )
        )
    elif args.action == "verify":
        result = verify(args.root.resolve())
        print(
            json.dumps(
                {
                    "verified_version": result["version"],
                    "source_input_sha256": result["source_input_sha256"],
                    "files": len(cast(list[dict[str, object]], result["source_input_files"])),
                },
                sort_keys=True,
            )
        )
    else:
        delta = stage(
            args.worker.resolve(),
            central=args.central.resolve(),
            coordination=args.coordination.resolve(),
            destination=args.destination.resolve(),
        )
        print(
            json.dumps(
                {
                    "backend_paths": len(delta),
                    "source_snapshot": "accepted central plus backend delta",
                }
            )
        )


if __name__ == "__main__":
    main()
