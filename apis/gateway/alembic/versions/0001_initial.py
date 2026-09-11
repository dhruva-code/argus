"""initial schema (private-beta baseline)

Revision ID: 0001_initial
Revises:
Create Date: 2026-09-10

Creates the complete current schema from `Base.metadata` in one shot. This
is a genuine architectural correction, not a workaround: migrations
0002-0009 originally each added their own tables/columns/enum-type
increments on top of a *frozen* M1-only 0001 snapshot — but 0001 was
written as `Base.metadata.create_all(bind=bind)` with no table filter, so
it silently tracked whatever `app/models.py` looks like *today* rather than
a fixed point in time. That only breaks on a genuine `downgrade base` ->
`upgrade head` replay against an empty database (never on an incremental
upgrade of an already-migrated one, which is why it went unnoticed for a
long time): SQLAlchemy's Postgres-native-ENUM support additionally ties
`CREATE TYPE` to the whole metadata object rather than to just the tables
being created, so 0001 ended up creating every enum type and every
evolved column any later migration also (correctly, on its own) tried to
create — a hard duplicate-object conflict.

Since this is a private-beta repository with no production database
depending on the old incremental history, migrations 0002-0009 were turned
into documented no-ops (see each file) rather than deleted, so their
revision IDs/history stay intact for anyone who already has a database
stamped partway through that chain. 0001 is now the single source of truth
for the full schema; add new tables/columns as new migrations *after*
0009, the same as any other project.
"""

from __future__ import annotations

from alembic import op

from app.db import Base
from app import models  # noqa: F401

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
