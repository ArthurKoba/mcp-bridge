#!/usr/bin/env python3
"""Derive canonical Hatch wheel producer inputs and selective app pin impact.

The ONLY Coolify watch source remains each Compose x-watch-path-coolify.
Wheel producer input is derived from Hatch's pyproject.toml packages/force-
include and lock/docs. Runtime impact roots live in module-local wheel pins,
NOT Watch arrays. This emits review evidence; it does not publish/update pins.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import tomllib
from watch_impact import ROOT, generated_impact, watch_list

EXCLUDED={'__pycache__','.git','.venv','.ruff_cache','.mypy_cache','node_modules'}
class GraphRejected(RuntimeError): pass

def wheel_sources(source_root: Path) -> set[str]:
    """Use Backend A13's actual accepted 395-input canonical release graph.

    Hatch package roots are cross-checked, not silently substituted for the
    larger source-input graph (which also includes release/lock scripts).
    """
    manifest_file = source_root / 'services/common/release_provenance.json'
    manifest = json.loads(manifest_file.read_text())
    if manifest.get('schema') != 'briareus-full-wheel-source-v1':
        raise GraphRejected('missing canonical A13 release source manifest')
    entries = manifest.get('source_input_files')
    if not isinstance(entries, list) or len(entries) < 1:
        raise GraphRejected('release input inventory missing')
    import hashlib
    normalized = json.dumps(entries, separators=(',', ':'), sort_keys=True, ensure_ascii=True).encode()
    digest = hashlib.sha256(normalized).hexdigest()
    if digest != manifest.get('source_input_sha256'):
        raise GraphRejected('release source inventory digest mismatch')
    package = tomllib.loads((source_root / 'pyproject.toml').read_text())
    if manifest.get('version') != package['project']['version']:
        raise GraphRejected('source package version differs from source manifest')
    hatch = package['tool']['hatch']['build']['targets']['wheel']
    inputs: set[str] = set()
    for entry in entries:
        name = entry.get('path')
        if not isinstance(name, str) or name.startswith('/') or '..' in name.split('/'):
            raise GraphRejected('unsafe release manifest file path')
        origin = source_root / name
        if not origin.is_file() or origin.is_symlink():
            raise GraphRejected('source input absent: '+name)
        if name in inputs:
            raise GraphRejected('duplicate source input '+name)
        inputs.add(name)
    for package_input in [*hatch['packages'], *hatch.get('force-include', {})]:
        root = source_root/package_input
        if not root.exists():
            raise GraphRejected('Hatch wheel package path missing: '+package_input)
        if root.is_file():
            items = [root]
        else:
            items = (x for x in root.rglob('*') if x.is_file())
        for item in items:
            if EXCLUDED.intersection(item.relative_to(source_root).parts) or item.suffix == '.pyc':
                continue
            key = item.relative_to(source_root).as_posix()
            # The manifest is a generated release output and cannot include
            # itself in a self-contained digest; it is separately versioned.
            if key == 'services/common/release_provenance.json':
                continue
            if key not in inputs:
                raise GraphRejected('Hatch wheel file omitted from canonical source graph: '+key)
    if not {'pyproject.toml','uv.lock','README.md','LICENSE','.python-version','scripts/release_candidate.py'} <= inputs:
        raise GraphRejected('release producer input missing')
    return inputs

def app_pins() -> dict[str,dict]:
    registry=json.loads((ROOT/'APPLICATIONS.json').read_text())
    pins={}
    for app in registry['applications']:
        module=app['module']
        if module in {'data','admin-ui'}:continue
        pointer=app.get('wheel_pin_source')
        if pointer!=f'deploy/{module}/wheel-pin.json':raise GraphRejected('pin source differs: '+module)
        pins[module]=json.loads((ROOT/module/'wheel-pin.json').read_text())
    if len(pins)!=12:raise GraphRejected('12 Python consumer Apps required')
    return pins

def impact(changed: str,inputs: set[str],pins:dict[str,dict]) -> dict:
    if changed not in inputs:
        return {'wheel_rebuild':False,'direct_app_watch':generated_impact([changed])[changed],'candidate_apps':[]}
    # A full wheel must be rebuilt even when only one owner uses the changed source.
    if changed in {'pyproject.toml','uv.lock','README.md','LICENSE'}:
        candidates=list(pins)
    else:
        candidates=[m for m,p in pins.items() if any(
            changed==root or changed.startswith(root.rstrip('/')+'/')
            for root in p['impact_roots'])]
        if not candidates:
            # Incomplete import map: fail conservative; the orchestrator must
            # classify before selecting a new App pin, never silently drop it.
            candidates=list(pins)
    return {'wheel_rebuild':True,'direct_app_watch':generated_impact([changed])[changed],'candidate_apps':candidates,'candidate_selection_is_exhaustive':False,'requires_import_and_dynamic_dependency_review':True,'automatic_pin_bump':False,'action':'review full runtime and dynamic import closure before pin selection'}

def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root',type=Path,required=True)
    p.add_argument('--changed-file',action='append',default=[])
    p.add_argument('--sample-matrix',action='store_true')
    args=p.parse_args()
    sources=wheel_sources(args.source_root)
    pins=app_pins()
    for module,pin in pins.items():
        roots=pin.get('impact_roots')
        if not isinstance(roots,list) or not roots or any(not isinstance(x,str) or '..' in x for x in roots):
            raise GraphRejected('missing/invalid owner impact roots: '+module)
        watches=watch_list(module)
        expected={f'deploy/{module}/Dockerfile',f'deploy/{module}/Dockerfile.dockerignore',f'deploy/{module}/wheel-pin.json',f'deploy/{module}/docker-compose.yaml',f'deploy/{module}/docker-compose.coolify.yaml','deploy/install_wheel_release.py'}
        if set(watches)!=expected:
            raise GraphRejected(f'{module}: per-app watchers include wheel source or omit local build inputs')
    if args.changed_file:
        changed=args.changed_file
    elif args.sample_matrix:
        examples=['pyproject.toml','uv.lock','services/common/settings.py','services/identity/platform_runtime.py','services/projects/catalog_runtime.py','services/bridge/server.py','services/modules/files/runtime.py','scripts/alembic_owners/access/versions/0001_access_baseline.py','deploy/README.md','admin-web-app/src/app/App.vue']
        changed=examples
    else:changed=[]
    result={'wheel_source_file_count':len(sources),'producer_inputs':sorted(sources),'pinned_python_app_count':len(pins),'impact':{file:impact(file,sources,pins) for file in changed}}
    print(json.dumps(result,indent=2,ensure_ascii=False))

if __name__=='__main__':
    try:main()
    except (GraphRejected,KeyError,ValueError,OSError) as exc:
        print('WHEEL_GRAPH_REJECTED: '+str(exc),file=sys.stderr);raise SystemExit(1) from None
