#!/usr/bin/env python3
"""Read-only domain DB ownership inventory. This tool cannot provision/DDL or read secrets."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json',action='store_true')
    args=parser.parse_args()
    path=Path(__file__).resolve().parent/'config/owner-databases.json'
    data=json.loads(path.read_text())
    assert data['provisioning_status']=='source_only_owner_approval_required'
    assert len(data['initial'])==4
    if args.json:
        print(json.dumps(data,indent=2))
    else:
        print('SOURCE-ONLY OWNER DATABASES — NOT PROVISIONED')
        for row in data['initial']:
            print(f"{row['owner']}: database={row['database']} role={row['runtime_role']} runtime={row['role_env']},{row['secret_env']} DDL={row['migration_role']} ENV={row['migration_role_env']},{row['migration_secret_env']}")
        print('REQUIRES independent credentials/backup/role+DDL authority and explicit live-cutover approval')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
