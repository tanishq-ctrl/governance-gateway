"""The mandatory checks: a format check and a personal-data (PII) scan with redaction.

The patterns are those of the project's simulator (gsl.governance_rules), with an
optional leading "+" on telephone numbers so a redacted international number leaves no
stray sign behind. They find e-mail addresses, telephone numbers and national ID
numbers in the US SSN format; names and postal addresses are not detected.
"""

from __future__ import annotations

import re
from typing import Any

MAX_MESSAGE_CHARS = 4_000

EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}")
NATIONAL_ID = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
PHONE = re.compile(r"\+?(?:\d[\s\-().x]*){7,}")

#: In this order; the order decides which tag a match gets.
PII_KINDS = (("e-mail address", EMAIL), ("national ID", NATIONAL_ID),
             ("telephone number", PHONE))


def format_check(text: Any) -> bool:
    """A non-empty string of at most MAX_MESSAGE_CHARS characters."""
    return isinstance(text, str) and bool(text.strip()) and len(text) <= MAX_MESSAGE_CHARS


def pii_scan(text: str) -> tuple[bool, list[str], str]:
    """(no personal data found, kinds found, text with each match masked by its kind)."""
    found, redacted = [], text
    for kind, pattern in PII_KINDS:
        if pattern.search(redacted):
            found.append(kind)
            tag = f"[{kind.upper()}]"
            redacted = pattern.sub(lambda m: tag + m.group(0)[len(m.group(0).rstrip()):],
                                   redacted)
    return not found, found, redacted
