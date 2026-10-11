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
SHARED = re.compile(r'\{\{(team|project|environment)\.([A-Z][A-Z0-9_]*)\}\}')
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
    if registry['provisioning_status']!='source_only_uv_direct_live_provisioning_blocked':
        fatal('live Apply guard not present')
    if registry.get('management',{}).get('build_strategy')!='coolify_git_webhook_uv_cached_deps_noneditable_project':
        fatal('uv direct build source of truth is missing')
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
    if manifest.get('role_model') != 'single_owner_scoped_principal_runs_alembic_at_startup':
        fatal('runtime principal cannot own migrations in accepted D4 rollout')
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
        # Public domain routes must be declared only as canonical Coolify
        # magic keys. Never interpolate SERVICE_URL_* in Compose values:
        # Docker Compose resolves variables before Coolify can supply them.
        if module in {'admin-api', 'admin-ui'}:
            public_port = '8000' if module == 'admin-api' else '8080'
            service_key = f'briareus-{module}'
            public_key = 'PUBLIC_API_URL' if module == 'admin-api' else 'PUBLIC_UI_URL'
            magic_key = 'SERVICE_URL_' + service_key.upper().replace('-', '_') + '_' + public_port
            public_env = override['services'][service_key]['environment']
            if public_env.get(magic_key) != '/' or public_key in public_env:
                fatal(f'{module}: invalid Coolify magic domain or unnecessary PUBLIC_* URL')
            if any('${SERVICE_URL_' in str(v) for v in public_env.values()):
                fatal(f'{module}: SERVICE_URL_* must never be Compose-interpolated')
            exposed = base['services'][service_key].get('expose', [])
            if public_port not in [str(x) for x in exposed]:
                fatal(f'{module}: public domain port mismatch')
            if module == 'admin-api':
                if public_env.get('OTEL_SERVICE_NAMESPACE') != '${OTEL_SERVICE_NAMESPACE:?}':
                    fatal('admin-api: namespace must be required explicit ENV')
                if public_env.get('OTEL_SERVICE_NAME') != '${OTEL_SERVICE_NAME:?}':
                    fatal('admin-api: OTEL_SERVICE_NAME must be operator-required')
        # Telemetry configuration is never named SERVICE_*, which Coolify
        # reserves for generated values. Match real OpenTelemetry resource keys
        # through our Briareus-specific environment aliases.
        if module not in {'data','admin-ui'}:
            service = f'briareus-{module}'
            env = override['services'][service]['environment']
            if env.get('OTEL_SERVICE_NAMESPACE') != '${OTEL_SERVICE_NAMESPACE:?}':
                fatal(f'{module}: missing required Project OTEL service namespace')
            if env.get('OTEL_DEPLOYMENT_ENVIRONMENT_NAME') != '${OTEL_DEPLOYMENT_ENVIRONMENT_NAME:?}':
                fatal(f'{module}: missing required Environment OTEL deployment name')
            if env.get('OTEL_SERVICE_NAME') != '${OTEL_SERVICE_NAME:?}':
                fatal(f'{module}: OTEL_SERVICE_NAME must be an operator-required runtime input')
            shared = a['shared_variables']
            if shared.get('OTEL_SERVICE_NAMESPACE') != '{{project.OTEL_SERVICE_NAMESPACE}}':
                fatal(f'{module}: wrong Project telemetry namespace reference')
            if shared.get('OTEL_DEPLOYMENT_ENVIRONMENT_NAME') != '{{environment.OTEL_DEPLOYMENT_ENVIRONMENT_NAME}}':
                fatal(f'{module}: wrong Environment telemetry deployment reference')
        for service_env in (base['services'].values(), override['services'].values()):
            for entry in service_env:
                if any(key in entry.get('environment',{}) for key in ('SERVICE_NAMESPACE','DEPLOYMENT_ENVIRONMENT')):
                    fatal(f'{module}: legacy telemetry ENV detected')
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
                actual=override['services'][service]['environment'].get(key)
                if module=='data' and service=='briareus-postgres' and key in {
                    f'{owner}_POSTGRES_{field}' for owner in ('IDENTITY','ACCESS','CONTROL','CATALOG')
                    for field in ('USER','PASSWORD')
                }:
                    if value != '$'+'{'+key+':-}' or actual != '{{project.'+key+'}}':
                        fatal(f'data: PostgreSQL bootstrap credential must be a protected Project reference: {key}')
                elif actual!=value:
                    fatal(f'{module}: base/Coolify ENV mismatch {key}')
            used=set(REQUIRED.findall(str(override['services'][service]['environment'])))
            bindings=a.get('shared_variables',{})
            allowed_required=set(bindings) | ({'OTEL_SERVICE_NAME'} if module not in {'data','admin-ui'} else set())
            if not used<=allowed_required:
                fatal(f'{module}: required ENV lacks scoped reference: {used-allowed_required}')
            for key,ref in bindings.items():
                match=SHARED.fullmatch(ref)
                # Only owner App inputs use canonical aliases for
                # separately qualified Environment Shared credentials.
                owner_key=(
                    OWNERS[module][2]+'_'+key
                    if module in OWNERS and key in {'POSTGRES_USER','POSTGRES_PASSWORD'} else key
                )
                if (match is None or match.group(2)!=owner_key
                        or owner_key not in cfg[match.group(1)+'_shared']):
                    fatal(f'{module}: bad Shared binding {key}')
        if module=='data':
            if (ROOT/module/'greenfield_schema.py').exists():
                fatal('manual metadata initializer is forbidden')
            expected_data={
                'deploy/data/Dockerfile','deploy/data/Dockerfile.dockerignore',
                'deploy/data/owner-bootstrap.psql',
                'deploy/data/postgres-entrypoint.sh',
                'deploy/data/docker-compose.yaml','deploy/data/docker-compose.coolify.yaml',
            }
            if set(watches)!=expected_data:
                fatal('data: bootstrap inputs not fully watched')
            docker=(ROOT/module/'Dockerfile')
            shell=(ROOT/module/'postgres-entrypoint.sh')
            sql=(ROOT/module/'owner-bootstrap.psql')
            if not all(p.is_file() for p in (docker,shell,sql)):
                fatal('data: missing existing-PostgreSQL-container owner bootstrap source')
            if 'FROM postgres:18.6-alpine' not in docker.read_text():
                fatal('data: upstream PostgreSQL version changed')
            copy_ignore=(ROOT/module/'Dockerfile.dockerignore').read_text()
            if any(x not in copy_ignore for x in ('!deploy/data/owner-bootstrap.psql',
                                                   '!deploy/data/postgres-entrypoint.sh')):
                fatal('data: Dockerfile context silently excludes bootstrap source')
            if 'ENTRYPOINT ["/usr/local/bin/briareus-postgres-entrypoint"]' not in docker.read_text():
                fatal('data: ordinary PostgreSQL entrypoint bootstrap gate missing')
            if base['services']['briareus-postgres']['build'] != {
                'context':'../..','dockerfile':'deploy/data/Dockerfile'
            }:
                fatal('data: PostgreSQL must build only its existing extended image')
            if 'test -f /run/briareus-owner-databases-ready' not in str(base['services']['briareus-postgres']['healthcheck']):
                fatal('data: readiness must gate on four provisioned owner stores')
            if 'docker-entrypoint.sh "$@" &' not in shell.read_text() or 'ON_ERROR_STOP=1' not in shell.read_text():
                fatal('data: SQL bootstrap not owned by existing PostgreSQL lifecycle')
            for db in ('briareus_identity','briareus_access','briareus_platform','briareus_resources'):
                if db not in sql.read_text():
                    fatal(f'data: missing provisioned domain database: {db}')
            continue
        docker=ROOT/module/'Dockerfile'
        if not docker.is_file() or a['dockerfile']!=f'deploy/{module}/Dockerfile':
            fatal(f'{module}: missing source Dockerfile')
        if f'deploy/{module}/Dockerfile' not in watches:
            fatal(f'{module}: Dockerfile changes not watched')
        if module!='admin-ui':
            if (ROOT/module/'wheel-pin.json').exists() or a.get('wheel_pin_source'):
                fatal(f'{module}: deprecated external wheel pin still active')
            if a.get('activation')!='source_only_uv_direct_image_build_live_activation_blocked':
                fatal(f'{module}: live activation guard removed')
            dockertext=docker.read_text()
            for forbidden in ('deploy/wheel_artifacts/', 'install_wheel_release.py',
                              'PYTHONPATH=', 'SERVICE_VERSION='):
                if forbidden in dockertext:
                    fatal(f'{module}: obsolete wheel distribution/runtime shortcut: {forbidden}')
            expected_deps='uv sync --frozen --no-dev --no-install-project'
            if module=='web':
                expected_deps='uv sync --frozen --no-dev --group web --no-install-project'
            if f'RUN --mount=type=cache,target=/root/.cache/uv,sharing=shared {expected_deps}' not in dockertext:
                fatal(f'{module}: missing cached dependency-only build layer')
            expected_project='uv sync --frozen --no-dev --no-editable --reinstall-package briareus'
            if module=='web':
                expected_project='uv sync --frozen --no-dev --group web --no-editable --reinstall-package briareus'
            if f'RUN --mount=type=cache,target=/root/.cache/uv,sharing=shared {expected_project}' not in dockertext:
                fatal(f'{module}: Briareus wheel not force-reinstalled from current Git source')
            if dockertext.index(expected_deps)>dockertext.index('COPY services/') or dockertext.index(expected_project)<dockertext.index('COPY scripts/'):
                fatal(f'{module}: dependency cache or actual project installation wrong order')
            if 'CMD ' not in dockertext or 'uv sync ' in dockertext.split('CMD ')[-1]:
                fatal(f'{module}: runtime should run service without uv sync')
            expected={f'deploy/{module}/Dockerfile',f'deploy/{module}/Dockerfile.dockerignore',
                      f'deploy/{module}/docker-compose.yaml',f'deploy/{module}/docker-compose.coolify.yaml',
                      'pyproject.toml','uv.lock','README.md','LICENSE','.python-version','services/**','scripts/**'}
            if set(watches)!=expected:
                fatal(f'{module}: full source build has uncovered inputs/watches')
            ignore=(ROOT/module/'Dockerfile.dockerignore').read_text()
            for needed in ('!pyproject.toml','!uv.lock','!README.md','!LICENSE','!.python-version',
                           '!services/','!services/**','!scripts/','!scripts/**'):
                if needed not in ignore:
                    fatal(f'{module}: missing narrow Docker COPY input: {needed}')
            for src in docker_copies(docker):
                if src.startswith('deploy/'):
                    fatal(f'{module}: obsolete deploy install artifact reached image')
                path=source_root/src.rstrip('/')
                if not path.exists() or not watch_covered(src,watches):
                    fatal(f'{module}: actual Docker COPY input uncovered: {src}')
        else:
            for src in docker_copies(docker):
                path=ROOT/src.removeprefix('deploy/') if src.startswith('deploy/') else source_root/src
                if not path.exists() or not watch_covered(src,watches):
                    fatal(f'{module}: UI COPY input missing/unwatched {src}')
        if module in OWNERS:
            # A failed DB/Alembic/trust prerequisite must stop the owner
            # process and stay stopped, not spin in an endless restart loop.
            if base['services'][f'briareus-{module}'].get('restart') != 'no':
                fatal(f'{module}: failed owner startup must not auto-restart')
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
            if env.get('OTEL_SERVICE_NAME')!='${OTEL_SERVICE_NAME:?}':
                fatal(f'{module}: OTel service_name mismatches real owner_runtime telemetry identity')
            if env['POSTGRES_DB']!=db or env['POSTGRES_HOST']!='briareus-postgres':
                fatal(f'{module}: stale / shared god database target')
            if env['POSTGRES_USER']!='${POSTGRES_USER:?}' or env['POSTGRES_PASSWORD']!='${POSTGRES_PASSWORD:?}':
                fatal(f'{module}: owner App must use canonical POSTGRES_USER/PASSWORD inputs')
            if any(k.startswith('MIGRATION_POSTGRES_') for k in env):
                fatal(f'{module}: second DB migration credential contract returned')
            for app_key in ('POSTGRES_USER','POSTGRES_PASSWORD'):
                ref='{{project.'+env_key+'_'+app_key+'}}'
                if a['shared_variables'].get(app_key)!=ref:
                    fatal(f'{module}: owner-specific role reference absent: {app_key}')
            if any(k.startswith('MIGRATION_POSTGRES_') for k in a['shared_variables']):
                fatal(f'{module}: legacy migration Shared variables returned')
            if record.get('owner_role')!=f'briareus_{owner}_owner':
                fatal(f'{module}: one owner-specific role must own only its database')
            if record.get('owner_role_may_apply_own_schema_ddl') is not True:
                fatal(f'{module}: owner cannot apply its own Alembic revisions')
            for flag in ('owner_role_superuser_allowed','owner_role_createdb_allowed',
                         'owner_role_createrole_allowed',
                         'owner_role_cross_database_grants_allowed'):
                if record.get(flag) is not False:
                    fatal(f'{module}: unsafe owner role privilege: {flag}')
            if (source_root/'services/common/owner_migration_roles.py').exists():
                fatal('obsolete separate migrator module returned')
            runtime_source=(source_root/'services/common/owner_runtime.py').read_text()
            if 'await migrate_owner(database, local, phase_change=diagnostic_phase)' not in runtime_source:
                fatal('normal owner startup no longer runs own Alembic revisions')
            if 'result = await verify_owner(database, local)' not in runtime_source:
                fatal('independent read-only verification after migration missing')
            if 'alembic_greenfield' in docker.read_text()+cool.read_text():
                fatal(f'{module}: old global Alembic graph in deploy image')
            # Domain owner migrations ship inside the local uv-installed Hatch package.
            # Shared services/scripts input is intentionally watched until a reviewed split.
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
    if any(ROOT.glob('*/wheel-pin.json')) or (ROOT/'install_wheel_release.py').exists():
        fatal('old external wheel release artifacts still active')
    print('UV_DIRECT_SOURCE_STATIC_PASS; 14 Apps, 28 YAML, 12 first-party uv images, four owner DBs')
    print('Dependencies cached before source COPY; local package force-reinstalled non-editably at BUILD; no uv sync in service CMD.')
    print('Actual Coolify image BUILD, new SQL role/DB/OS/C2 acceptance not established by STATIC.')


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
