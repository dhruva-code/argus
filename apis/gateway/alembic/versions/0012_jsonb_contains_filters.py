"""Fix .contains()-filtered JSON columns to real JSONB

Revision ID: 0012_jsonb_contains_filters
Revises: 0011_ai_report_settings

`assets.technologies`, `endpoints.tags`, and `endpoints.sources` are
filtered with SQLAlchemy's `.contains()` (the `technology=`/`tag=`/
`source=` query params on GET /assets and /endpoints). On a plain
Postgres `json` column (the original type — `json` and `jsonb` are
different types in Postgres; SQLAlchemy's generic `JSON` maps to `json`),
`.contains()` compiles to `column LIKE '%' || value || '%'`, and Postgres
has no `LIKE` operator for `json` at all — every request using one of
these filters was failing with `UndefinedFunctionError: operator does not
exist: json ~~ text` (a 500, not silently wrong data). `jsonb` supports
this properly via the `@>` containment operator, which `.contains()`
compiles to once the column's type is known to be JSONB.

`USING <col>::jsonb` is safe and lossless for existing data — every JSON
value is also a valid JSONB value.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0012_jsonb_contains_filters"
down_revision: str | None = "0011_ai_report_settings"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COLUMNS = [
    ("assets", "technologies"),
    ("endpoints", "tags"),
    ("endpoints", "sources"),
]


def upgrade() -> None:
    for table, column in _COLUMNS:
        op.execute(f"ALTER TABLE {table} ALTER COLUMN {column} TYPE jsonb USING {column}::jsonb")


def downgrade() -> None:
    for table, column in _COLUMNS:
        op.execute(f"ALTER TABLE {table} ALTER COLUMN {column} TYPE json USING {column}::json")
