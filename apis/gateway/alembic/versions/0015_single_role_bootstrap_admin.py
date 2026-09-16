"""Single-role model: collapse Role down to super_admin; drop registration/
email-verification/password-reset columns

Revision ID: 0015_single_role_bootstrap_admin
Revises: 0014_ai_triage_findings_secrets

Every account is now a super admin (app/core/rbac.py grants every
permission to the one remaining role) — public registration, the
first-run /setup wizard, invite/role-assignment, and forgot-password have
all been removed from the API; the only way an account is created is
`python -m app.bootstrap_admin` (run automatically by install.sh). See
docs/AUTHENTICATION.md.

Every existing membership is reassigned to super_admin (all pre-existing
roles already had a strict superset-or-equal permission relationship to
today's single all-permissions role, so no access is gained that a prior
org_admin/security_lead/etc. didn't already effectively have via the
existing is_superuser-or-role permission resolution — and the removed
lower roles like viewer/researcher only ever existed via the now-removed
invite endpoint). The `role` column/type stay (rather than being dropped
outright) so MeResponse.role, OrgSummary.role, and every other existing
"role" reference across the API/frontend keep working unchanged.

The `users` column drops are existence-guarded (see
app/_migration_guards.py): on a database built via the full 0001->head
chain from empty (any brand-new install), 0001_initial's
`Base.metadata.create_all()` runs against *current* `app/models.py` —
which, by the time this migration exists, no longer declares those
columns at all — so plain `drop_column` calls would fail with "column
does not exist". Confirmed by actually running the full chain against a
fresh Postgres database, not assumed.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

from app._migration_guards import column_exists

revision: str = "0015_single_role_bootstrap_admin"
down_revision: str | None = "0014_ai_triage_findings_secrets"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OLD_ROLES = ("super_admin", "org_admin", "security_lead", "security_analyst", "researcher", "viewer")


def upgrade() -> None:
    bind = op.get_bind()
    is_pg = bind.dialect.name == "postgresql"

    # Every existing account becomes a super admin.
    op.execute("UPDATE memberships SET role = 'super_admin'")
    op.execute("UPDATE users SET email_verified = true")

    if is_pg:
        # Shrinking a Postgres enum TYPE's value set isn't a direct ALTER —
        # swap in a new type with only the one value we now use.
        op.execute("ALTER TYPE role RENAME TO role_old")
        op.execute("CREATE TYPE role AS ENUM ('super_admin')")
        op.execute(
            "ALTER TABLE memberships ALTER COLUMN role TYPE role USING role::text::role, "
            "ALTER COLUMN role SET DEFAULT 'super_admin'"
        )
        op.execute("DROP TYPE role_old")
    else:
        # SQLite (tests) has no real enum type to shrink — the column is
        # already a plain VARCHAR with app-level validation.
        with op.batch_alter_table("memberships") as batch:
            batch.alter_column("role", server_default="super_admin")

    with op.batch_alter_table("users") as batch:
        batch.alter_column("email_verified", server_default=sa.true())
        for col in (
            "email_verify_token_hash",
            "email_verify_expires",
            "pending_email",
            "password_reset_token_hash",
            "password_reset_expires",
        ):
            if column_exists("users", col):
                batch.drop_column(col)


def downgrade() -> None:
    bind = op.get_bind()
    is_pg = bind.dialect.name == "postgresql"

    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("password_reset_expires", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("password_reset_token_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("pending_email", sa.String(320), nullable=True))
        batch.add_column(sa.Column("email_verify_expires", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("email_verify_token_hash", sa.String(64), nullable=True))
        batch.alter_column("email_verified", server_default=sa.false())

    if is_pg:
        op.execute("ALTER TYPE role RENAME TO role_new")
        values_sql = ", ".join(f"'{v}'" for v in _OLD_ROLES)
        op.execute(f"CREATE TYPE role AS ENUM ({values_sql})")
        op.execute(
            "ALTER TABLE memberships ALTER COLUMN role TYPE role USING role::text::role, "
            "ALTER COLUMN role SET DEFAULT 'viewer'"
        )
        op.execute("DROP TYPE role_new")
    else:
        with op.batch_alter_table("memberships") as batch:
            batch.alter_column("role", server_default="viewer")
