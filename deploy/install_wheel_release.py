#!/usr/bin/env python3
"""Offline noneditable Briareus wheel installer; no network and no source overlay.

Use at Docker image BUILD once the immutable reviewed wheel has been transported
into the image's verified build context. This never downloads a wheel or guesses
an OCI registry. Pins remain module-local and source-reviewed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


class ReleaseRejected(RuntimeError):
    pass

def parse_pin(path: Path) -> dict:
    obj=json.loads(path.read_text())
    required={'schema','distribution','version','filename','sha256','source_tree','release_status'}
    if not required <= obj.keys() or obj['schema']!='briareus-wheel-pin-v1' or obj['distribution']!='briareus':
        raise ReleaseRejected('not a reviewed Briareus wheel pin schema')
    if obj['release_status'] not in {'review_only_not_publishable','reviewer_accepted_immutable'}:
        raise ReleaseRejected('unknown artifact acceptance state')
    import re
    if re.fullmatch(r'[0-9a-f]{64}',str(obj['sha256'])) is None:
        raise ReleaseRejected('missing strong wheel content digest')
    if re.fullmatch(r'briareus-[A-Za-z0-9_.+]+-py3-none-any\.whl',str(obj['filename'])) is None:
        raise ReleaseRejected('unsafe/foreign wheel filename')
    if obj['version'] != obj['filename'].removeprefix('briareus-').removesuffix('-py3-none-any.whl').replace('_','-'):
        raise ReleaseRejected('pin version does not match wheel filename')
    if not str(obj['source_tree']):
        raise ReleaseRejected('missing explicit source provenance')
    if obj['release_status']=='reviewer_accepted_immutable':
        if re.fullmatch(r'[0-9a-f]{40}',obj['source_tree']) is None:
            raise ReleaseRejected('published accepted immutable wheel requires exact Git tree SHA')
        if re.fullmatch(r'[0-9a-f]{64}',str(obj.get('source_input_sha256',''))) is None:
            raise ReleaseRejected('published accepted immutable wheel requires source SHA256')
    return obj

def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pin',type=Path,required=True)
    parser.add_argument('--wheel-directory',type=Path,required=True)
    parser.add_argument('--python',type=Path,required=True)
    parser.add_argument('--allow-review-artifact',action='store_true',help='offline source check only; forbidden in runnable image')
    args=parser.parse_args()
    pin=parse_pin(args.pin)
    if pin['release_status']!='reviewer_accepted_immutable' and not args.allow_review_artifact:
        raise ReleaseRejected('review-only wheel cannot enter runnable Docker release')
    artifact=args.wheel_directory/pin['filename']
    if not artifact.is_file() or artifact.is_symlink():
        raise ReleaseRejected('immutable pinned wheel unavailable from verified build context')
    digest=hashlib.file_digest(artifact.open('rb'), 'sha256').hexdigest()
    if digest!=pin['sha256']:
        raise ReleaseRejected('wheel artifact SHA256 mismatch')
    env=dict(os.environ)
    # Force no editable source tree / no import from unchecked working directory.
    env.pop('PYTHONPATH',None)
    subprocess.run(['uv','pip','install','--offline','--no-deps','--python',str(args.python),str(artifact)],env=env,check=True)
    inspected=r'''import json,sys
from pathlib import Path
from importlib.metadata import distribution, version
from importlib.util import find_spec
root=Path(sys.prefix).resolve()
actual=version('briareus')
location=distribution('briareus')
mods=('common','identity','authorization','projects','agents','bridge','modules','presentation')
for module in mods:
 spec=find_spec(module)
 if spec is None or spec.origin is None or not Path(spec.origin).resolve().is_relative_to(root):
  raise SystemExit('source shadowing or missing installed package: '+module)
provenance_file=Path(location.locate_file('common/release_provenance.json'))
if not provenance_file.is_file():
 raise SystemExit('installed wheel lacks source provenance')
source_manifest=json.loads(provenance_file.read_text())
if source_manifest.get('schema')!='briareus-full-wheel-source-v1' or source_manifest.get('version')!=actual:
 raise SystemExit('installed wheel provenance schema/version is invalid')
files=[str(item).replace('\\','/') for item in location.files or ()]
for name in ('identity','access','platform','resources','files','runtime','reverse','ingest'):
 if not any(f.startswith('common/alembic_owners/'+name+'/versions/') and f.endswith('.py') for f in files):
  raise SystemExit('missing owner Alembic migration in installed wheel: '+name)
print(json.dumps({'version':actual,'installed_package_count':len(mods),'owner_graphs':8,'source_input_sha256':source_manifest.get('source_input_sha256')}))'''
    result=subprocess.run([str(args.python),'-I','-c',inspected],env=env,check=True,text=True,capture_output=True)
    report=json.loads(result.stdout)
    if report['version']!=pin['version']:
        raise ReleaseRejected('installed distribution metadata disagrees with immutable wheel pin')
    if report.get('source_input_sha256')!=pin.get('source_input_sha256'):
        raise ReleaseRejected('installed wheel source provenance differs from reviewed release pin')
    print('WHEEL_INSTALLED_AND_METADATA_VERIFIED',pin['version'],pin['sha256'][:16],report['owner_graphs'],'owner graphs')

if __name__=='__main__':
    try:main()
    except (ReleaseRejected,ValueError,OSError,subprocess.CalledProcessError,json.JSONDecodeError) as exc:
        print(f'WHEEL_RELEASE_REJECTED: {type(exc).__name__}: {str(exc)[:250]}',file=sys.stderr)
        raise SystemExit(1) from None
