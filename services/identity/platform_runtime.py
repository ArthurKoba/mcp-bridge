"""Identity owns briareus_identity and its Alembic startup lifecycle."""

from common.owner_runtime import create_owner_app

app = create_owner_app("identity")
