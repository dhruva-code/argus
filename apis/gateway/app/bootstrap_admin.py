"""Creates the default operator account and organization.

Run with:  python -m app.bootstrap_admin

Idempotent — safe to re-run; does nothing if the account already exists
(use --reset-password to rotate the password on an existing account
instead). Unlike app/seed.py (demo/synthetic project data, gated behind
ARGUS_ALLOW_SEED, meant for local dev only), this creates a single real
account meant to actually be used: no demo project, no fake scan history,
no fake tool-health rows.

The password comes from ARGUS_DEFAULT_ADMIN_PASSWORD if set (install.sh
sets this in .env so a fresh install ends with known, documented
credentials instead of a one-time value only visible in that terminal's
scrollback) — otherwise a fresh random one is generated on every run that
creates or resets the account, never hardcoded in source, never logged.
Change it (or enable MFA) after first login — see Settings -> Security.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import secrets
import sys

from sqlalchemy import select

from app.core import security
from app.db import SessionLocal, create_all
from app.models import Membership, Organization, Role, User
from app.seed_profiles import ensure_builtin_profiles

DEFAULT_ORG_NAME = "Ashborn"
DEFAULT_ORG_SLUG = "ashborn"
DEFAULT_ADMIN_EMAIL = "ashborn-admin@ashborn.local"
DEFAULT_ADMIN_NAME = "Ashborn-admin"


def _generate_password() -> str:
    configured = os.getenv("ARGUS_DEFAULT_ADMIN_PASSWORD", "").strip()
    if configured:
        return configured
    # 24 URL-safe chars ~= 142 bits of entropy — well above the 12-char
    # minimum the rest of the platform enforces on user-chosen passwords.
    return secrets.token_urlsafe(18)


async def bootstrap(*, reset_password: bool = False) -> None:
    await create_all()
    async with SessionLocal() as session:
        org = await session.scalar(select(Organization).where(Organization.slug == DEFAULT_ORG_SLUG))
        if org is None:
            org = Organization(name=DEFAULT_ORG_NAME, slug=DEFAULT_ORG_SLUG)
            session.add(org)
            await session.flush()
            print(f"Created organization: {DEFAULT_ORG_NAME}")

        await ensure_builtin_profiles(session, org.id)

        user = await session.scalar(select(User).where(User.email == DEFAULT_ADMIN_EMAIL))
        password: str | None = None
        if user is None:
            password = _generate_password()
            user = User(
                email=DEFAULT_ADMIN_EMAIL,
                full_name=DEFAULT_ADMIN_NAME,
                password_hash=security.hash_password(password),
                is_superuser=True,
                email_verified=True,
            )
            session.add(user)
            await session.flush()
            print(f"Created user: {DEFAULT_ADMIN_NAME} <{DEFAULT_ADMIN_EMAIL}>")
        elif reset_password:
            password = _generate_password()
            user.password_hash = security.hash_password(password)
            print(f"Password reset for: {DEFAULT_ADMIN_NAME} <{DEFAULT_ADMIN_EMAIL}>")
        else:
            print(f"Account already exists: {DEFAULT_ADMIN_NAME} <{DEFAULT_ADMIN_EMAIL}> — no changes made.")
            print("Re-run with --reset-password to rotate its password.")

        membership = await session.scalar(
            select(Membership).where(Membership.user_id == user.id, Membership.org_id == org.id)
        )
        if membership is None:
            session.add(Membership(user_id=user.id, org_id=org.id, role=Role.org_admin))

        await session.commit()

    if password:
        configured = bool(os.getenv("ARGUS_DEFAULT_ADMIN_PASSWORD", "").strip())
        print("")
        print("=" * 60)
        print("  DEFAULT ADMIN CREDENTIALS")
        print(f"  Email:    {DEFAULT_ADMIN_EMAIL}")
        print(f"  Password: {password}")
        if configured:
            print("  (from ARGUS_DEFAULT_ADMIN_PASSWORD in .env — change it for any")
            print("   production/internet-facing/multi-user deployment.)")
        else:
            print("  (freshly generated — shown once, not stored anywhere.)")
        print("  Change this (Settings -> Security) after first login.")
        print("=" * 60)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reset-password", action="store_true",
        help="Generate and set a new password for the existing default admin account.",
    )
    args = parser.parse_args()
    asyncio.run(bootstrap(reset_password=args.reset_password))


if __name__ == "__main__":
    sys.exit(main())
