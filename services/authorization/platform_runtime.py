"""Access owns ONLY briareus_access, never Identity, Control or Catalog DDL.

No public C1-B2/C2 business routes are mounted by this startup.
"""

from __future__ import annotations

from common.owner_runtime import create_owner_app

app = create_owner_app("access")
