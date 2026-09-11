"""Shared Pydantic field types."""

from __future__ import annotations

import re
from typing import Annotated

from pydantic import AfterValidator

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _valid_email(v: str) -> str:
    v = v.strip().lower()
    if not _EMAIL_RE.match(v) or len(v) > 320:
        raise ValueError("not a valid email address")
    return v


# Permissive email type: unlike pydantic's EmailStr it accepts lab/reserved TLDs
# such as .test and .local, which are common for authorized internal engagements
# and for this platform's own demo data.
Email = Annotated[str, AfterValidator(_valid_email)]
