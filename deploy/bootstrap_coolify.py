#!/usr/bin/env python3
"""Reconcile Briareus DEV Coolify resources from deploy/APPLICATIONS.json.

Dry-run is the default. --apply may create only the dedicated Briareus project,
development environment, briareus-net standalone Destination, and the current declared
Git-backed Applications after a reviewed release. It NEVER starts/deploys an Application, changes DNS,
OAuth issuer, legacy resources, or invents secret values.

The source registry declares Team/Environment Shared bindings by variable name.
Coolify first materializes editable `${KEY}`/`${KEY:?}` Compose variables;
then `--apply` binds them to Shared references without ever reading values.
This is config-only: no application starts, database changes, or implicit deploy.
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

SERVER_NAME = "tambov"
SERVER_UUID = "5jrwg4jddi4axlzn2lspubrn"
PROJECT_NAME = "briareus"
ENVIRONMENT_NAME = "development"
NETWORK_NAME = "briareus-net"
NETWORK_LABEL = "Briareus Network"
REPOSITORY = "ArthurKoba/briareus"
REPOSITORY_URL = "https://github.com/ArthurKoba/briareus.git"
RESOURCE_ID = re.compile(r"[a-z0-9]{24}\Z")
REQUIRED = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\:\?\}")
INTERPOLATED = re.compile(r"\$\{([A-Z][A-Z0-9_]*)(?::-[^}]*)?(?::\?)?\}")
SHARED_REF = re.compile(r"\{\{(team|project|environment)\.([A-Z][A-Z0-9_]*)\}\}\Z")
GENERATED_DOMAIN = re.compile(r"\bSERVICE_(?:URL|FQDN)_[A-Z0-9_]+\b")


class BootstrapError(RuntimeError):
    pass


def api(base: str, token: str, method: str, route: str, payload: dict | None = None):
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = Request(f"{base.rstrip('/')}/api/v1/{route}", method=method, headers=headers, data=data)
    try:
        with urlopen(request, timeout=20) as response:
            raw = response.read(1024 * 512)
    except HTTPError as exc:
        body = exc.read(2048).decode("utf-8", "replace")
        raise BootstrapError(f"Coolify HTTP {exc.code} for {method} /{route}: {body[:300]}") from None
    except (URLError, TimeoutError) as exc:
        raise BootstrapError(f"Coolify transport failure for {method} /{route}: {type(exc).__name__}") from None
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw.decode("utf-8", "replace").strip()


def post_once(base: str, token: str, route: str, payload: dict, refetch):
    """POST exactly once; on uncertainty refetch expected state and never blind retry."""
    try:
        return api(base, token, "POST", route, payload)
    except BootstrapError as exc:
        observed = refetch()
        if observed is not None:
            print(f"POST outcome uncertain but expected state is now visible for /{route}; continuing without retry")
            return observed
        raise BootstrapError(f"{exc}; expected state absent after failed POST; refusing automatic retry") from None


def normalize_origin(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path.rstrip("/"):
        raise BootstrapError("--coolify-url must be a bare trusted HTTPS origin")
    return value.rstrip("/")


def read_registry(root: Path) -> dict:
    registry = json.loads((root / "APPLICATIONS.json").read_text())
    if registry.get("repository") != REPOSITORY or registry.get("server") != SERVER_NAME or registry.get("environment") != ENVIRONMENT_NAME:
        raise BootstrapError("APPLICATIONS.json does not describe canonical Briareus DEV target")
    apps = registry.get("applications")
    if not isinstance(apps, list) or len(apps) < 11 or len({x.get("name") for x in apps}) != len(apps):
        raise BootstrapError("APPLICATIONS.json requires nonempty unique Application names")
    if len({x.get("module") for x in apps}) != len(apps):
        raise BootstrapError("APPLICATIONS.json must have explicit unique module identities")
    return registry


def required_variables(root: Path, app: dict) -> list[str]:
    module = app["module"]
    source = (root / module / "docker-compose.coolify.yaml").read_text()
    return sorted(set(REQUIRED.findall(source)))


def autogenerate_domain(root: Path, app: dict) -> bool:
    module = app["module"]
    source = (root / module / "docker-compose.coolify.yaml").read_text()
    return bool(GENERATED_DOMAIN.search(source))


def watch_paths(root: Path, app: dict) -> str:
    module = app["module"]
    source = (root / module / "docker-compose.coolify.yaml").read_text()
    marker = "x-watch-path-coolify:\n"
    if not source.startswith(marker):
        raise BootstrapError(f"{module}: missing top-level x-watch-path-coolify")
    result=[]
    for line in source[len(marker):].splitlines():
        if not line.strip() and result:
            break
        if not line.startswith("  - "):
            if result:
                break
            continue
        value=json.loads(line[4:])
        if not isinstance(value,str) or value.startswith("/") or ".." in value.split("/"):
            raise BootstrapError(f"{module}: unsafe Watch Path")
        result.append(value)
    if not result:
        raise BootstrapError(f"{module}: no Watch Paths")
    return "\n".join(result)


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--coolify-url", default="https://coolify.koba-nexus.ru")
    parser.add_argument("--branch", required=True, help="reviewed published Briareus branch/ref, e.g. main")
    parser.add_argument("--expected-version", help="exact installed Coolify version; required with --apply")
    parser.add_argument("--apply", action="store_true")
    args=parser.parse_args()
    base=normalize_origin(args.coolify_url)
    root=Path(__file__).resolve().parent
    registry=read_registry(root)
    # A checked-out SOURCE DRAFT must never be used to create/reconcile live Apps.
    # Enabling apply requires accepted source/publication status AND an independently
    # authorized Coolify write token/version; no environment variable bypass.
    if args.apply and registry.get("provisioning_status") != "approved_published_live_configuration":
        raise BootstrapError("owner DB/source staging is NOT approved for Coolify mutation")
    config=registry.get("configuration_contract")
    if not isinstance(config, dict):
        raise BootstrapError("APPLICATIONS.json missing configuration_contract")
    allowed_scopes={"team":frozenset(config.get("team_shared", [])),
                    "project":frozenset(config.get("project_shared", [])),
                    "environment":frozenset(config.get("environment_shared", []))}
    if config.get("read_secret_values") is not False:
        raise BootstrapError("secret read policy must remain disabled")
    bindings_by_app={}
    for app in registry["applications"]:
        module=app["module"]
        source=(root/module/"docker-compose.coolify.yaml").read_text()
        declared=set(INTERPOLATED.findall(source))
        bindings=app.get("shared_variables",{})
        if not isinstance(bindings,dict):
            raise BootstrapError(f"{module}: shared_variables must be a mapping")
        for key,ref in bindings.items():
            match=SHARED_REF.fullmatch(ref) if isinstance(ref,str) else None
            if not match or key != match.group(2) or key not in allowed_scopes[match.group(1)]:
                raise BootstrapError(f"{module}: unapproved Shared variable binding for {key}")
            if key not in declared:
                raise BootstrapError(f"{module}: {key} is not a Compose interpolation input")
        bindings_by_app[app["name"]]=bindings
    if args.branch.startswith("TO_BE_") or not re.fullmatch(r"[A-Za-z0-9._/-]{1,160}", args.branch):
        raise BootstrapError("invalid/unreviewed Git branch/ref")

    required_by_app={app["name"]: required_variables(root, app) for app in registry["applications"]}
    print(f"PLAN: {len(registry['applications'])} Applications, server={SERVER_NAME}, environment={ENVIRONMENT_NAME}, network={NETWORK_NAME}, branch={args.branch}")
    for app in registry["applications"]:
        print(f"  {app['name']}: base={app['base_directory']} required_inputs={','.join(required_by_app[app['name']]) or '-'}")
    all_required=set().union(*required_by_app.values())
    classified=set().union(*(set(x) for x in bindings_by_app.values()))
    unknown_required=sorted(all_required-classified)
    if unknown_required:
        raise BootstrapError(
            "unclassified required variables in Compose: " + ", ".join(unknown_required)
        )
    for name,bindings in bindings_by_app.items():
        if bindings:
            print(f"  SHARED BINDINGS {name} (names/scopes only): " + ", ".join(f"{key}={ref}" for key,ref in sorted(bindings.items())))
    if not args.apply and not os.environ.get("COOLIFY_API_TOKEN"):
        print("DRY RUN SOURCE-ONLY: no COOLIFY_API_TOKEN; no remote read/write performed")
        return 0
    token=os.environ.get("COOLIFY_API_TOKEN", "")
    if not token:
        raise BootstrapError("COOLIFY_API_TOKEN is required for remote reconciliation")
    version=str(api(base,token,"GET","version")).strip('"')
    print(f"REMOTE: Coolify version={version}")
    if args.apply and (not args.expected_version or version != args.expected_version):
        raise BootstrapError("--apply requires exact --expected-version matching installed Coolify")

    servers=api(base,token,"GET","servers")
    server=next((x for x in servers if x.get("uuid")==SERVER_UUID and x.get("name")==SERVER_NAME),None)
    if not server:
        raise BootstrapError("canonical Tambov server not found")

    projects=api(base,token,"GET","projects")
    project=next((x for x in projects if x.get("name")==PROJECT_NAME),None)
    if not project:
        if not args.apply:
            print("MISSING: Coolify project briareus")
            return 2
        project=post_once(base,token,"projects",{"name":PROJECT_NAME,"description":"Briareus isolated DEV"},lambda: next((x for x in api(base,token,"GET","projects") if x.get("name")==PROJECT_NAME),None))
    project_uuid=project.get("uuid")
    if not project_uuid:
        raise BootstrapError("Briareus project UUID unavailable")

    environments=api(base,token,"GET",f"projects/{project_uuid}/environments")
    environment=next((x for x in environments if x.get("name")==ENVIRONMENT_NAME),None)
    if not environment:
        if not args.apply:
            print("MISSING: Briareus development environment")
            return 2
        environment=post_once(base,token,f"projects/{project_uuid}/environments",{"name":ENVIRONMENT_NAME},lambda: next((x for x in api(base,token,"GET",f"projects/{project_uuid}/environments") if x.get("name")==ENVIRONMENT_NAME),None))
    env_uuid=environment.get("uuid")
    if not env_uuid:
        raise BootstrapError("development environment UUID unavailable")

    # Intentionally do not GET Project Shared Variables: the D/agent surface must
    # not read secret values. Existence/scope is verified separately through a
    # metadata-only operator surface before deployment.


    destinations=api(base,token,"GET",f"servers/{SERVER_UUID}/destinations")
    destination=next((x for x in destinations if x.get("network")==NETWORK_NAME),None)
    if destination and (destination.get("type")!="standalone" or destination.get("name")!=NETWORK_LABEL):
        raise BootstrapError("briareus-net exists with unexpected Coolify ownership metadata")
    if not destination:
        if not args.apply:
            print("MISSING: briareus-net Destination")
            return 2
        payload={"name":NETWORK_LABEL,"network":NETWORK_NAME,"type":"standalone"}
        destination=post_once(base,token,f"servers/{SERVER_UUID}/destinations",payload,lambda: next((x for x in api(base,token,"GET",f"servers/{SERVER_UUID}/destinations") if x.get("network")==NETWORK_NAME),None))
    destination_uuid=destination.get("uuid")
    if not destination_uuid:
        raise BootstrapError("Briareus Destination UUID unavailable")

    applications=api(base,token,"GET","applications")
    created=[]
    missing_apps=[]
    parser_pending=[]
    for spec in registry["applications"]:
        name=spec["name"]
        app=next((x for x in applications if x.get("name")==name),None)
        desired_watch=watch_paths(root,spec)
        if app:
            if app.get("git_repository") not in {REPOSITORY,REPOSITORY_URL,REPOSITORY_URL.removesuffix('.git')} or app.get("base_directory")!=spec["base_directory"]:
                raise BootstrapError(f"{name}: existing resource has unexpected repository/base directory; refusing takeover")
            print(f"EXISTS: {name} uuid={app.get('uuid')}")
        else:
            if not args.apply:
                print(f"MISSING: {name}")
                missing_apps.append(name)
                continue
            payload={
                "project_uuid":project_uuid,
                "environment_uuid":env_uuid,
                "environment_name":ENVIRONMENT_NAME,
                "server_uuid":SERVER_UUID,
                "destination_uuid":destination_uuid,
                "name":name,
                "git_repository":REPOSITORY_URL,
                "git_branch":args.branch,
                "build_pack":"dockercompose",
                "base_directory":spec["base_directory"],
                "docker_compose_location":spec["docker_compose_location"],
                "watch_paths":desired_watch,
                "is_auto_deploy_enabled":False,
                "is_preview_deployments_enabled":False,
                "autogenerate_domain":autogenerate_domain(root, spec),
                "instant_deploy":False,
            }
            def refetch(name=name):
                return next((x for x in api(base,token,"GET","applications") if x.get("name")==name),None)
            app=post_once(base,token,"applications/public",payload,refetch)
            created.append(name)
            applications=api(base,token,"GET","applications")
            app=next((x for x in applications if x.get("name")==name),app)
            print(f"CREATED_CONFIG_ONLY: {name} uuid={app.get('uuid')}; NOT DEPLOYED")
        app_uuid=app.get("uuid")
        if not app_uuid or not RESOURCE_ID.fullmatch(app_uuid):
            raise BootstrapError(f"{name}: invalid Coolify Application UUID")
        # Reconcile safe source/watch state; auto deploy remains off until later explicit acceptance.
        patch={"git_branch":args.branch,"base_directory":spec["base_directory"],"docker_compose_location":spec["docker_compose_location"],"watch_paths":desired_watch,"is_auto_deploy_enabled":False,"is_preview_deployments_enabled":False,"autogenerate_domain":autogenerate_domain(root, spec)}
        if args.apply:
            api(base,token,"PATCH",f"applications/{app_uuid}",patch)
        envs=api(base,token,"GET",f"applications/{app_uuid}/envs")
        by_key={x.get("key"):x for x in envs if isinstance(x,dict) and not x.get("is_preview")}
        missing_parsed=[key for key in set(required_by_app[name])|set(bindings_by_app[name]) if key not in by_key]
        if missing_parsed:
            print(f"PARSER_PENDING: {name} has not materialized required env keys: {', '.join(missing_parsed)}")
            parser_pending.append(name)
            continue
        for key,desired_value in sorted(bindings_by_app[name].items()):
            if args.apply:
                api(base,token,"PATCH",f"applications/{app_uuid}/envs",{
                    "key":key,"value":desired_value,"is_preview":False,"is_literal":False,
                    "is_multiline":False,"is_shown_once":False,"is_runtime":True,
                    "is_buildtime":False,
                    "comment":"Briareus Shared variable reference (no secret value exposed)"})
        verified=api(base,token,"GET",f"applications/{app_uuid}")
        if verified.get("watch_paths")!=desired_watch or verified.get("base_directory")!=spec["base_directory"] or verified.get("git_branch")!=args.branch:
            raise BootstrapError(f"{name}: Coolify did not persist exact source/watch configuration")
    if created:
        print("CREATED BUT NOT DEPLOYED: "+", ".join(created))
    if missing_apps:
        print("DRY RUN INCOMPLETE: missing Applications: "+", ".join(missing_apps))
        return 2
    if parser_pending:
        print("RECONCILE INCOMPLETE: wait for Coolify Compose parsing, then rerun; no deploy performed")
        return 4
    print("RECONCILE COMPLETE: configuration only; no Application start/deploy endpoint was called")
    return 0


if __name__=="__main__":
    try:
        raise SystemExit(main())
    except (BootstrapError,OSError,ValueError,json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}",file=sys.stderr)
        raise SystemExit(1) from None
