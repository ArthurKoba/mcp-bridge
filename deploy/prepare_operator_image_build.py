#!/usr/bin/env python3
"""Prepare a PRIVATE, offline Docker build context for an owner-operated image build.

No Docker invocation, Git write, network, deploy, DB/role, or secret access.
Consumes an independently accepted published wheel pin, wheel bytes, and
Git checkout matching the immutable Briareus source provenance. Never copies
an artifact into the repository or into a shared wheel artifact cache.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

from install_wheel_release import ReleaseRejected, parse_pin
from wheel_source_graph import wheel_sources

ALLOWED_MODULES=frozenset({
    'identity','authorization','platform','resources','admin-api','gateway',
    'files','terminal','web','svc','infrastructure','reverse',
})


def _git_tree(source:Path) -> str:
    result=subprocess.run(['git','-C',str(source),'rev-parse','HEAD^{tree}'],
        text=True,check=True,capture_output=True)
    return result.stdout.strip()


def prepare(*,stage:Path,source:Path,artifact:Path,destination:Path,module:str) -> dict:
    if module not in ALLOWED_MODULES:
        raise ReleaseRejected('not an allowed first-party wheel image')
    if destination.exists() or destination.is_symlink():
        raise ReleaseRejected('operator build context already exists; refusing overwrite')
    pinfile=stage/module/'wheel-pin.json'
    pin=parse_pin(pinfile)
    if pin['release_status']!='reviewer_accepted_immutable':
        raise ReleaseRejected('NOT READY: wheel pin is still SOURCE REVIEW ONLY')
    if not artifact.is_file() or artifact.is_symlink() or artifact.name!=pin['filename']:
        raise ReleaseRejected('reviewed wheel binary with exact filename missing')
    if hashlib.sha256(artifact.read_bytes()).hexdigest()!=pin['sha256']:
        raise ReleaseRejected('wheel binary mismatch against accepted immutable pin')
    reviewed_root=source/'services/common/release_provenance.json'
    provenance=json.loads(reviewed_root.read_text())
    if provenance['source_input_sha256']!=pin['source_input_sha256'] or provenance['version']!=pin['version']:
        raise ReleaseRejected('source is not exactly the reviewed wheel provenance')
    # A release source manifest cannot embed its own Git tree SHA (self-reference).
    # The reviewed pin is published in a *later* selection commit and names the
    # immutable wheel producer Git tree. Do not require a circular self-hash.
    if provenance.get('published_git_tree') not in (None,pin['source_tree']):
        raise ReleaseRejected('source manifest declared a contradictory Git tree')
    # The source Git tree for the *producer* can differ from the later pin
    # selection commit; never compare to the pin commit's self-referential tree.
    if not isinstance(pin['source_tree'],str) or len(pin['source_tree'])!=40:
        raise ReleaseRejected('published source tree must be exact SHA1')
    if _git_tree(source)!=pin['source_tree']:
        raise ReleaseRejected('checked-out wheel producer Git tree differs from accepted tree')
    # Reject source files changed locally behind an unchanged HEAD^{tree}.
    subprocess.run([sys.executable,str(source/'scripts/release_candidate.py'),
        'verify','--root',str(source)],check=True,capture_output=True,text=True)
    _=wheel_sources(source)
    if destination.is_relative_to(source) or destination.is_relative_to(stage):
        raise ReleaseRejected('build context must be outside any source/Git staging tree')
    scratch=destination.with_name(destination.name+'.tmp')
    if scratch.exists():
        raise ReleaseRejected('unsafe preexisting temporary build destination')
    try:
        scratch.mkdir(parents=True)
        for name in ('pyproject.toml','uv.lock'):
            shutil.copy2(source/name,scratch/name)
        (scratch/'deploy'/module).mkdir(parents=True)
        for name in ('Dockerfile','Dockerfile.dockerignore','wheel-pin.json'):
            shutil.copy2(stage/module/name,scratch/'deploy'/module/name)
        shutil.copy2(stage/'install_wheel_release.py',scratch/'deploy/install_wheel_release.py')
        wheelhouse=scratch/'deploy/wheel_artifacts'
        wheelhouse.mkdir(parents=True)
        shutil.copy2(artifact,wheelhouse/artifact.name)
        if hashlib.sha256((wheelhouse/artifact.name).read_bytes()).hexdigest()!=pin['sha256']:
            raise ReleaseRejected('copied wheel mismatch')
        # Review-only evidence, not a mutable ENV or executable remote fetch.
        (scratch/'BUILD_RECEIPT.json').write_text(json.dumps({
            'module':module,'wheel_version':pin['version'],'wheel_sha256':pin['sha256'],
            'source_input_sha256':pin['source_input_sha256'], 'wheel_producer_git_tree':pin['source_tree'],
            'status':'PREPARED_FOR_HUMAN_DOCKER_BUILD_NOT_IMAGE_BUILT',
        },indent=2)+'\n')
        scratch.rename(destination)
    finally:
        if scratch.exists():
            shutil.rmtree(scratch)
    return {'module':module,'context':str(destination),'dockerfile':f'deploy/{module}/Dockerfile',
        'wheel_sha256':pin['sha256'],'version':pin['version']}


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage',type=Path,required=True)
    parser.add_argument('--source-root',type=Path,required=True)
    parser.add_argument('--wheel',type=Path,required=True)
    parser.add_argument('--module',choices=sorted(ALLOWED_MODULES),required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=prepare(stage=args.stage.resolve(),source=args.source_root.resolve(),
        artifact=args.wheel.resolve(),destination=args.output.resolve(),module=args.module)
    print(json.dumps(result,ensure_ascii=False,indent=2))
    # Docker image tags cannot contain PEP440 local-version '+'; the canonical
    # wheel version/digest remains exact in the attested BUILD_RECEIPT.json.
    tag=result['version'].replace('+','_')+'-'+result['wheel_sha256'][:12]
    print('OPERATOR STEP AFTER REVIEW: cd',result['context'],
          '&& docker build --file',result['dockerfile'],'--tag',
          f'briareus-{result["module"]}:{tag}','.')
    return 0


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except (ReleaseRejected,ValueError,OSError,KeyError,subprocess.CalledProcessError,json.JSONDecodeError) as exc:
        print(f'BUILD_CONTEXT_REJECTED: {exc}',file=sys.stderr)
        raise SystemExit(1) from None
