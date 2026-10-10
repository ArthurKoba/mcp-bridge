"""Source-only owner metadata loader; never combines owner databases or UoWs.

Registration imports the concrete model declarations, but returns only the
named owner's own SQLAlchemy registry. It never connects or migrates on import.
"""

from __future__ import annotations

from importlib import import_module

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

from common.platform_db import (
    AccessBase,
    CatalogBase,
    ControlBase,
    FilesBase,
    IdentityBase,
    IngestBase,
    OwnerName,
    ReverseBase,
    RuntimeBase,
)

_OWNER_MODELS: dict[OwnerName, tuple[type[DeclarativeBase], tuple[str, ...]]] = {
    "identity": (IdentityBase, ("identity._persistence", "identity._owner_ledger")),
    "access": (
        AccessBase,
        (
            "authorization._platform_persistence",
            "authorization._session_persistence",
            "authorization._service_identity_persistence",
        ),
    ),
    "platform": (
        ControlBase,
        (
            "teams._persistence",
            "projects._persistence",
            "agents._persistence",
            "authorization._scoped_events_persistence",
            "projects._control_ledger",
        ),
    ),
    "resources": (
        CatalogBase,
        (
            "projects._resource_persistence",
            "authorization._platform_persistence",
            "projects._catalog_ledger",
        ),
    ),
    "files": (FilesBase, ("projects._file_quota_persistence", "projects._files_ledger")),
    "runtime": (RuntimeBase, ("projects._runtime_persistence", "projects._execution_ledger")),
    "reverse": (ReverseBase, ("projects._native_import_persistence", "projects._reverse_ledger")),
    "ingest": (IngestBase, ("authorization._browser_telemetry_persistence",)),
}


def owner_metadata(owner: OwnerName) -> MetaData:
    base, modules = _OWNER_MODELS[owner]
    for module in modules:
        import_module(module)
    metadata = base.metadata
    if not metadata.tables:
        raise RuntimeError(f"{owner} has no mapped tables")
    for table in metadata.tables.values():
        for fk in table.foreign_keys:
            if fk.column.table.key not in metadata.tables:
                raise RuntimeError(f"{owner} has an illegal cross-database FK")
    return metadata
