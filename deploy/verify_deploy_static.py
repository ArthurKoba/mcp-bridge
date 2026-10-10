#!/usr/bin/env python3
"""Read-only static verifier for D4 four-owner release candidate; no tests/network/DB.

A11 source is external and unaccepted while in Backend worktree. Use
--source-root to inspect that exact worktree, then repeat against accepted
orchestrator fan-in. Never promote staging-source PASS into Docker/DB_RUNTIME.
"""
from __future__ import annotations

import argparse
import json
import re
import shlex
from pathlib import Path

import yaml
from watch_impact import REPO, ROOT, watch_list

OWNERS = {
    'identity': ('identity','briareus_identity','IDENTITY'),
    'authorization': ('access','briareus_access','ACCESS'),
    'platform': ('platform','briareus_platform','CONTROL'),
    'resources': ('resources','briareus_resources','CATALOG'),
}
MODULES = frozenset({
    'data','identity','authorization','platform','resources','admin-api','admin-ui',
    'gateway','files','terminal','web','svc','infrastructure','reverse',
})
REQUIRED = re.compile(r'\$\{([A-Z][A-Z0-9_]*):\?\}')
SHARED = re.compile(r'\{\{(team|environment)\.([A-Z][A-Z0-9_]*)\}\}')
NETWORK = {'briareus':{'external':True,'name':'briareus-net'}}


def fatal(reason: str) -> None:
    raise RuntimeError(reason)


def docker_copies(path: Path) -> list[str]:
    copies=[]
    for raw in path.read_text().splitlines():
        if not raw.lstrip().startswith('COPY '):
            continue
        args=shlex.split(raw.strip())[1:]
        if any(x.startswith('--from=') for x in args):
            continue
        copies.extend(x for x in args[:-1] if not x.startswith('--'))
    return copies


def watch_covered(source: str, watches: list[str]) -> bool:
    return source in watches or any(
        x.endswith('/**') and (source==x[:-3] or source.startswith(x[:-3]+'/'))
        for x in watches
    )


def run(source_root: Path, allow_pending: bool) -> None:
    registry=json.loads((ROOT/'APPLICATIONS.json').read_text())
    apps=registry['applications']
    if {a['module'] for a in apps} != MODULES or len(apps)!=len(MODULES):
        fatal('exact 14 module registry is required')
    if len({a['name'] for a in apps})!=len(apps):
        fatal('duplicate Application display name')
    if {p.name for p in ROOT.iterdir() if p.is_dir() and p.name not in {'__pycache__', '.ruff_cache'}} != MODULES:
        fatal('wrong deploy module directories')
    if registry['provisioning_status']!='source_only_packaging_v1_unpublished_artifact_delivery_blocked':
        fatal('live Apply guard not present')
    management=registry.get('management',{})
    if management.get('operator_image_build_preparer')!='deploy/prepare_operator_image_build.py' or not (ROOT/'prepare_operator_image_build.py').is_file():
        fatal('approved operator-run build context tool missing')
    if management.get('wheel_artifact_delivery_verified') is not False:
        fatal('Coolify artifact delivery cannot be asserted before real proof')
    docs=sorted(p.name for p in ROOT.glob('*.md'))
    if docs != ['README.md']:
        fatal(f'duplicate active deployment manuals: {docs}')
    if (ROOT/'FANIN.json').exists():
        fatal('obsolete provider-parent FANIN must not be active')
    cfg=registry['configuration_contract']
    manifest=json.loads((ROOT/'data/config/owner-databases.json').read_text())
    rows={x['module']:x for x in manifest['initial']}
    if set(rows)!=set(OWNERS) or manifest['provisioning_status']!='source_only_owner_approval_required':
        fatal('owner DB manifest incomplete or not gated')
    if manifest.get('role_model') != 'separate_owner_scoped_runtime_and_migration_principals_required':
        fatal('runtime principal cannot own migrations in accepted D4 rollout')
    release_manifest=json.loads((source_root/'services/common/release_provenance.json').read_text())
    if release_manifest.get('schema')!='briareus-full-wheel-source-v1' or not release_manifest.get('source_input_sha256'):
        fatal('Backend A13 release provenance absent or schema invalid')
    release_pins=set()
    if manifest['legacy_database_do_not_migrate']!='briareus_dev':
        fatal('live historical DB may not be repurposed')
    if any(not v for v in manifest['immutable_guards'].values()):
        fatal('one or more DB/source safety guards disabled')
    for module in MODULES:
        a=next(x for x in apps if x['module']==module)
        name=next(iter(a['compose_services']),None)
        if not name or len(a['compose_services'])!=(2 if module=='data' else 1):
            fatal(f'{module}: wrong declared service count')
        if module!='data' and name!=f'briareus-{module}':
            fatal(f'{module}: environment leaks into service naming')
        if a['base_directory']!=f'/deploy/{module}' or a['docker_compose_location']!='/docker-compose.coolify.yaml':
            fatal(f'{module}: invalid source path')
        if a['watch_paths_source']!=f'deploy/{module}/docker-compose.coolify.yaml#x-watch-path-coolify':
            fatal(f'{module}: duplicate/mispointed Watch Paths registry')
        plain=ROOT/module/'docker-compose.yaml'
        cool=ROOT/module/'docker-compose.coolify.yaml'
        base=yaml.safe_load(plain.read_text())
        override=yaml.safe_load(cool.read_text())
        if base['networks']!=override['networks'] or base['networks']!=NETWORK:
            fatal(f'{module}: external network ownership mismatch')
        if base.get('volumes',{})!=override.get('volumes',{}):
            fatal(f'{module}: volume mapping changed between Compose files')
        if set(base['services'])!=set(a['compose_services']) or set(override['services'])!=set(a['compose_services']):
            fatal(f'{module}: registry/Compose services differ')
        watches=watch_list(module)
        for path in watches:
            if path in {'deploy/README.md','deploy/SHA256SUMS','deploy/APPLICATIONS.json','deploy/watch_impact.py'} or path.startswith('docs/'):
                fatal(f'{module}: source-doc change triggers redeploy')
        if f'deploy/{module}/docker-compose.yaml' not in watches or f'deploy/{module}/docker-compose.coolify.yaml' not in watches:
            fatal(f'{module}: Compose watch missing')
        for service,body in base['services'].items():
            if 'ports' in body or body.get('network_mode') == 'host':
                fatal(f'{module}: public host-port exposed')
            if body['networks']['briareus']['aliases']!=[service]:
                fatal(f'{module}: network alias mismatch')
            ext=override['services'][service]['extends']
            if ext!={'file':'docker-compose.yaml','service':service}:
                fatal(f'{module}: bad Coolify extends')
            for key,value in body.get('environment',{}).items():
                if override['services'][service]['environment'].get(key)!=value:
                    fatal(f'{module}: base/Coolify ENV mismatch {key}')
            used=set(REQUIRED.findall(str(override['services'][service]['environment'])))
            bindings=a.get('shared_variables',{})
            if not used<=set(bindings):
                fatal(f'{module}: required ENV lacks scoped reference: {used-set(bindings)}')
            for key,ref in bindings.items():
                match=SHARED.fullmatch(ref)
                if match is None or key!=match.group(2) or key not in cfg[match.group(1)+'_shared']:
                    fatal(f'{module}: bad Shared binding {key}')
        if module=='data':
            if any((ROOT/module/n).exists() for n in ('Dockerfile','greenfield_schema.py')):
                fatal('manual schema initializer returned')
            continue
        docker=ROOT/module/'Dockerfile'
        if not docker.is_file() or a['dockerfile']!=f'deploy/{module}/Dockerfile':
            fatal(f'{module}: missing source Dockerfile')
        if f'deploy/{module}/Dockerfile' not in watches:
            fatal(f'{module}: Dockerfile changes not watched')
        if module!='admin-ui':
            pin=ROOT/module/'wheel-pin.json'
            if not pin.is_file() or a.get('wheel_pin_source')!=f'deploy/{module}/wheel-pin.json':
                fatal(f'{module}: release-pin file not declared independently')
            from install_wheel_release import parse_pin
            obj=parse_pin(pin)
            release_pins.add((obj['version'],obj['sha256'],obj.get('source_input_sha256')))
            if obj['version']!=release_manifest.get('version') or obj.get('source_input_sha256')!=release_manifest.get('source_input_sha256'):
                fatal(f'{module}: pinned wheel differs from accepted A13 source digest/version')
            if not obj.get('source_tree','').startswith('PENDING_'):
                fatal(f'{module}: unapproved published Git tree guessed')
            if obj.get('release_status')!='review_only_not_publishable':
                fatal(f'{module}: no independent reviewer-approved immutable artifact delivery yet')
            if a.get('activation')!='wheel_review_only_no_proven_artifact_delivery_or_live_authorization':
                fatal(f'{module}: release activity not held until wheel delivery accepted')
            if set(watches)!={
                f'deploy/{module}/Dockerfile',
                f'deploy/{module}/Dockerfile.dockerignore',
                f'deploy/{module}/docker-compose.yaml',
                f'deploy/{module}/docker-compose.coolify.yaml',
                f'deploy/{module}/wheel-pin.json',
                'deploy/install_wheel_release.py',
            }:
                fatal(f'{module}: per-app watchers do not match local pin/install/Coolify inputs')
            dockertext=docker.read_text()
            if 'PYTHONPATH=' in dockertext or 'COPY services/' in dockertext or 'COPY scripts/' in dockertext:
                fatal(f'{module}: forbidden source overlay in installed wheel runtime')
            if 'uv sync ' not in dockertext or '--no-install-project' not in dockertext:
                fatal(f'{module}: missing locked third-party dependency layer')
            if 'deploy/install_wheel_release.py' not in dockertext or 'deploy/wheel_artifacts/' not in dockertext:
                fatal(f'{module}: canonical pinned release installer or transport input missing')
            if '--allow-review-artifact' in dockertext:
                fatal(f'{module}: a review-only artifact may not be installed in a runnable image')
            if 'wheel-pin.json' not in dockertext or '--python /app/.venv/bin/python' not in dockertext:
                fatal(f'{module}: no actual installed Briareus wheel verification')
            ignore=(ROOT/module/'Dockerfile.dockerignore').read_text()
            if '!deploy/wheel_artifacts/' not in ignore or '!deploy/install_wheel_release.py' not in ignore:
                fatal(f'{module}: missing explicit artifact COPY BuildKit whitelist')
            for src in docker_copies(docker):
                if src.startswith(('services/','scripts/')):
                    fatal(f'{module}: source COPY slipped past release pin')
                if src.startswith('deploy/wheel_artifacts/'):
                    # Publication/transport capability is NOT verified; source-only stage must
                    # remain explicitly non-runnable rather than claiming image BUILD.
                    if (ROOT/'wheel_artifacts').exists():
                        fatal('unreviewed wheel artifact pasted into Git staging')
                    continue
                path=(ROOT/src.removeprefix('deploy/')) if src.startswith('deploy/') else source_root/src
                if not path.exists():
                    fatal(f'{module}: Docker COPY source missing: {src}')
                if src.startswith('deploy/') and not watch_covered(src,watches):
                    fatal(f'{module}: non-wheel COPY input not watched: {src}')
        else:
            for src in docker_copies(docker):
                path=ROOT/src.removeprefix('deploy/') if src.startswith('deploy/') else source_root/src
                if not path.exists() or not watch_covered(src,watches):
                    fatal(f'{module}: UI COPY input missing/unwatched {src}')
        if module in OWNERS:
            expected_apps={'identity':'identity.platform_runtime:app',
                           'authorization':'authorization.platform_runtime:app',
                           'platform':'projects.control_runtime:app',
                           'resources':'projects.catalog_runtime:app'}
            if f'"{expected_apps[module]}"' not in docker.read_text():
                fatal(f'{module}: owner startup does not use the Backend A11 entrypoint')
            if (ROOT/module/'asgi.py').exists():
                fatal(f'{module}: redundant duplicated private owner ASGI entrypoint')
            owner, db, env_key=OWNERS[module]
            record=rows[module]
            if (record['owner'],record['database'],record['role_env'],record['secret_env'])!=(owner,db,env_key+'_POSTGRES_USER',env_key+'_POSTGRES_PASSWORD'):
                fatal(f'{module}: DB owner manifest mismatch')
            env=override['services'][f'briareus-{module}']['environment']
            expected_otel='authorization' if module=='authorization' else module
            if env.get('OTEL_SERVICE_NAME')!=expected_otel:
                fatal(f'{module}: OTel service_name mismatches real owner_runtime telemetry identity')
            if env['POSTGRES_DB']!=db or env['POSTGRES_HOST']!='briareus-postgres':
                fatal(f'{module}: stale / shared god database target')
            if env['POSTGRES_USER']!='${'+env_key+'_POSTGRES_USER:?}' or env['POSTGRES_PASSWORD']!='${'+env_key+'_POSTGRES_PASSWORD:?}':
                fatal(f'{module}: owner DB not bound to required scoped principal')
            if env.get('MIGRATION_POSTGRES_USER')!='${'+env_key+'_MIGRATION_POSTGRES_USER:?}' or env.get('MIGRATION_POSTGRES_PASSWORD')!='${'+env_key+'_MIGRATION_POSTGRES_PASSWORD:?}':
                fatal(f'{module}: separate owner-scoped migration role is not required')
            base_env=base['services'][f'briareus-{module}']['environment']
            if base_env.get('MIGRATION_POSTGRES_USER')!=env['MIGRATION_POSTGRES_USER'] or base_env.get('MIGRATION_POSTGRES_PASSWORD')!=env['MIGRATION_POSTGRES_PASSWORD']:
                fatal(f'{module}: migration role ENV absent from portable Compose')
            if record.get('migration_role_env')!=env_key+'_MIGRATION_POSTGRES_USER' or record.get('migration_secret_env')!=env_key+'_MIGRATION_POSTGRES_PASSWORD':
                fatal(f'{module}: DB manifest migration keys differ')
            if record.get('runtime_ddl_permitted') is not False or record.get('migration_role_ddl_only_own_db') is not True:
                fatal(f'{module}: migration role isolation invariant missing')
            if record.get('runtime_role')!=f'briareus_{owner}_runtime' or record.get('migration_role')!=f'briareus_{owner}_migrator':
                fatal(f'{module}: runtime/migration role identities not owner-specific')
            for flag in ('runtime_role_ddl_allowed','migration_role_superuser_allowed',
                         'migration_role_createdb_allowed','migration_role_createrole_allowed',
                         'migration_role_cross_database_grants_allowed'):
                if record.get(flag) is not False:
                    fatal(f'{module}: unsafe database role grant requested: {flag}')
            if 'owner_migration_roles.py' not in (source_root/'services/common/owner_runtime.py').read_text() and 'from common.owner_migration_roles import' not in (source_root/'services/common/owner_runtime.py').read_text():
                fatal('Backend source does not install dedicated migration role support')
            if 'alembic_greenfield' in docker.read_text()+cool.read_text():
                fatal(f'{module}: old global Alembic graph in deploy image')
            # Accepted source migrations are inside the canonical reviewed wheel.
            # There is no per-owner source COPY or migration watcher in module releases.
            if 'alembic_greenfield' in docker.read_text()+cool.read_text():
                fatal(f'{module}: old global Alembic graph remains reachable')
        elif module=='admin-api':
            env=override['services']['briareus-admin-api']['environment']
            if any(key.startswith('POSTGRES_') for key in env) or 'POSTGRES_USER' in a.get('shared_variables',{}):
                fatal('Admin API cannot retain direct shared database owner settings')
        elif module=='admin-ui':
            if 'OTLP_BEARER_TOKEN' in str(override):
                fatal('browser receives collector secret')
    for name in ('briareus-dev-postgres-v1','briareus-dev-valkey-v1'):
        if name not in (ROOT/'data/docker-compose.yaml').read_text():
            fatal('existing Data physical volume identity changed')
    if 'allow-owner' in (ROOT/'authorization/docker-compose.yaml').read_text():
        fatal('unapproved Auth runtime bypass')
    from wheel_source_graph import app_pins, wheel_sources
    sources=wheel_sources(source_root)
    if len(sources)!=len(release_manifest['source_input_files']):
        fatal('wheel source input set differs from accepted A13 release manifest')
    if len(release_pins)!=1 or len(app_pins())!=12:
        fatal('all 12 initial Python Apps must reference one A13 candidate')
    print('PACKAGING_V1_SOURCE_STATIC_PASS; 14 Apps, 12 candidate pinned wheel consumers, 28 YAML; four owner DBs')
    print('BUILD BLOCKED: immutable wheel transport to Git-backed Coolify build context NOT PROVEN; pins are review-only.')
    print('No image BUILD, live PostgreSQL, C2, or Coolify mutation acceptance.')


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=REPO)
    parser.add_argument('--allow-pending-owner-source',action='store_true')
    a=parser.parse_args()
    run(a.source_root,a.allow_pending_owner_source)
    return 0


if __name__=='__main__':
    try: raise SystemExit(main())
    except (ValueError,KeyError,AssertionError,RuntimeError,OSError) as exc:
        print(f'STATIC_REJECTED: {exc}')
        raise SystemExit(1) from None
