"""Retired legacy process startup: forbidden by Briareus storage ownership.

This entrypoint intentionally refuses to boot. D4 must package/activate the
independent Briareus owner startup after reviewing C1-B2/C2/DB grants.
Do not resurrect the old all-in-one database or OAuth/Admin compatibility.
"""

raise RuntimeError(
    "Legacy Admin runtime disabled; activate reviewed owner source only"
)
