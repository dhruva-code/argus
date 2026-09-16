"""Idempotency guards for Alembic migrations whose column/table might
already exist — imported from individual migration files under
alembic/versions/ (NOT placed inside alembic/ itself: that directory name
collides with the installed `alembic` package, so a migration-local
helper module belongs under `app/`, which every migration can already
import — see 0001_initial.py doing exactly that for `app.models`).

Why this is needed: 0001_initial runs `Base.metadata.create_all()` against
*current* `app/models.py` (see that file's own docstring) rather than a
frozen point-in-time schema — so any migration added after 0001 that adds
a column/table which has since become part of `app/models.py` will find
it already created when the full chain runs against a genuinely empty
database (a fresh install). Confirmed by actually running `alembic
upgrade head` against a fresh Postgres database, not assumed — see
migration 0010's docstring for the specific failure this was written for.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op


def add_column_if_missing(table: str, column: sa.Column) -> None:
    bind = op.get_bind()
    existing = {c["name"] for c in inspect(bind).get_columns(table)}
    if column.name not in existing:
        op.add_column(table, column)


def column_exists(table: str, column_name: str) -> bool:
    bind = op.get_bind()
    return column_name in {c["name"] for c in inspect(bind).get_columns(table)}


def create_table_if_missing(table_name: str, *args, **kwargs) -> None:
    bind = op.get_bind()
    if not inspect(bind).has_table(table_name):
        op.create_table(table_name, *args, **kwargs)
