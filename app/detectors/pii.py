"""Detects personal data (PII): Aadhaar, PAN, Indian phone numbers, emails."""

import re 
from app.detectors.models import Finding
_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_valid(number: str) -> bool:
    """Return True if the digit string passes the Verhoeff checksum."""
    check = 0
    for i, ch in enumerate(reversed(number)):
        check = _D[check][_P[i % 8][int(ch)]]
    return check == 0

AADHAAR_RE = re.compile(r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)")
# PAN: 5 letters, 4 digits, 1 letter. The 4th letter is the holder type.
PAN_RE = re.compile(r"\b[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z]\b")
# Indian mobile: optional +91 or 0, then 10 digits starting with 6-9.
PHONE_RE = re.compile(r"(?<![\d+])(?:\+91[ -]?|0)?[6-9]\d{4}[ -]?\d{5}(?!\d)")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

_SIMPLE_PATTERNS = {"PAN": PAN_RE, "PHONE": PHONE_RE, "EMAIL": EMAIL_RE}


def find_pii(text: str) -> list[Finding]:
    """Return every PII finding in the text."""
    findings: list[Finding] = []

    for match in AADHAAR_RE.finditer(text):
        digits = re.sub(r"\D", "", match.group())  # drop spaces / dashes
        if verhoeff_valid(digits):
            findings.append(Finding("AADHAAR", match.start(), match.end()))

    for category, pattern in _SIMPLE_PATTERNS.items():
        for match in pattern.finditer(text):
            findings.append(Finding(category, match.start(), match.end()))

    return findings



 