#!/usr/bin/env python3
"""Offline, generated Coolify Watch Paths impact from the ONLY source x-watch-path-coolify.

No second watch registry/list; no remote access, no tests or mock service.
"""
from __future__ import annotations

import argparse
import json
import sys
from fnmatch import fnmatchcase
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent if (ROOT.parent / "services").is_dir() else ROOT.parents[3] / "repo"


class ImpactError(RuntimeError):
    pass


def watch_list(module: str) -> list[str]:
    source = (ROOT / module / "docker-compose.coolify.yaml").read_text()
    header = "x-watch-path-coolify:\n"
    if not source.startswith(header):
        raise ImpactError(f"{module}: missing top-level watch source")
    paths: list[str] = []
    for line in source[len(header):].splitlines():
        if not line.startswith('  - '):
            if paths:
                break
            if line.strip():
                raise ImpactError(f"{module}: invalid watch YAML")
            continue
        item = json.loads(line[4:])
        if not isinstance(item, str) or not item or item.startswith(("/", "!")) or ".." in item.split("/"):
            raise ImpactError(f"{module}: unsafe watch path")
        if item in paths:
            raise ImpactError(f"{module}: duplicate watch path {item}")
        paths.append(item)
    if not paths:
        raise ImpactError(f"{module}: no watch paths")
    return paths


def matched(pattern: str, name: str) -> bool:
    if pattern.endswith("/**"):
        prefix = pattern[:-3].rstrip("/")
        return name.startswith(prefix + "/")
    return fnmatchcase(name, pattern)


def generated_impact(changed: list[str]) -> dict[str, list[str]]:
    registry = json.loads((ROOT / "APPLICATIONS.json").read_text())
    apps = registry["applications"]
    return {
        name: [app["module"] for app in apps if any(matched(w, name) for w in watch_list(app["module"]))]
        for name in changed
    }


def discovered_representatives(source_root: Path) -> list[str]:
    registry = json.loads((ROOT / "APPLICATIONS.json").read_text())
    representatives: list[str] = []
    for app in registry["applications"]:
        for pattern in watch_list(app["module"]):
            if pattern.endswith('/**'):
                root = source_root / pattern[:-3]
                if root.is_dir():
                    for file in sorted(root.rglob('*')):
                        if file.is_file() and not file.name.endswith(('.pyc', '.map')) and '__pycache__' not in file.parts:
                            representatives.append(file.relative_to(source_root).as_posix())
                            break
            elif not any(c in pattern for c in '*?['):
                source = ROOT / pattern.removeprefix('deploy/') if pattern.startswith('deploy/') else source_root / pattern
                if source.is_file():
                    representatives.append(pattern)
    representatives += ["deploy/README.md", "deploy/SHA256SUMS", "docs/architecture/storage-ownership-orchestrator-review.md"]
    return sorted(set(representatives))


def check_coverage(source_root: Path, allow_pending: bool) -> list[str]:
    missing=[]
    registry = json.loads((ROOT / "APPLICATIONS.json").read_text())
    for app in registry['applications']:
        module = app['module']
        for pattern in watch_list(module):
            if pattern.endswith('/**'):
                root = source_root / pattern[:-3]
                if not root.is_dir():
                    # Only full wheel producer watches source; App watches stay pin-local.
                    if allow_pending and pattern.startswith('scripts/alembic_owners/'):
                        missing.append(f'{module}: {pattern} (A11 NOT FAN-IN)')
                        continue
                    raise ImpactError(f"{module}: nonexistent directory watch {pattern}")
                if not any(p.is_file() for p in root.rglob('*')):
                    raise ImpactError(f"{module}: empty watched directory {pattern}")
            elif not any(c in pattern for c in '*?['):
                actual = ROOT / pattern.removeprefix('deploy/') if pattern.startswith('deploy/') else source_root / pattern
                if not actual.is_file():
                    raise ImpactError(f"{module}: nonexistent explicit watch {pattern}")
    impact = generated_impact([
        'deploy/README.md', 'admin-web-app/src/main.ts',
        'services/modules/files/project_files.py', 'scripts/alembic_greenfield/env.py',
    ])
    if impact['deploy/README.md']:
        raise ImpactError('documentation change triggers unexpected release')
    if impact['admin-web-app/src/main.ts'] != ['admin-ui']:
        raise ImpactError(f"Admin UI source impact incorrect: {impact['admin-web-app/src/main.ts']}")
    # Retired Alembic is absent from published source; generic scripts/**
    # conservatively covers real build inputs but cannot resurrect this job.
    if (source_root/'scripts/alembic_greenfield/env.py').exists():
        raise ImpactError('retired global migrator unexpectedly exists in source tree')
    # The current full Hatch project is installed into each Python image, so
    # its source touches every Python consumer while Data/UI remain separate.
    python_apps={a['module'] for a in registry['applications'] if a['module'] not in {'data','admin-ui'}}
    for owner in ('identity','access','platform','resources'):
        source=f'scripts/alembic_owners/{owner}/env.py'
        derived=generated_impact([source])
        if set(derived[source])!=python_apps:
            raise ImpactError(f'{owner}: shared Hatch source not watched by all Python consumers')
    return missing


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--changed-file', action='append', default=[], help='repo-relative changed file (repeatable)')
    parser.add_argument('--matrix', action='store_true', help='derive sample input->affected Apps from Compose watch lists')
    parser.add_argument('--check', action='store_true', help='static source coverage and isolation checks')
    parser.add_argument('--source-root', type=Path, default=REPO, help='source tree to check; default accepted central repo')
    parser.add_argument('--allow-pending-owner-source', action='store_true', help='explicitly mark missing A11 revision paths as UNVERIFIED')
    args = parser.parse_args()
    if args.check:
        missing = check_coverage(args.source_root, args.allow_pending_owner_source)
        if missing:
            print('WATCH_SOURCE_PENDING_A11:', '; '.join(missing))
        else:
            print('WATCH_SOURCE_COVERAGE_PASS')
    names = args.changed_file or (discovered_representatives(args.source_root) if args.matrix else [])
    if names:
        impacted = generated_impact(names)
        print(json.dumps(impacted, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ImpactError, ValueError, OSError, KeyError) as exc:
        print(f'WATCH_ERROR: {exc}', file=sys.stderr)
        raise SystemExit(1) from None
