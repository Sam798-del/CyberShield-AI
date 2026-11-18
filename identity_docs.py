"""Offline validation of identity documents (format + checksum rules).

This proves a number is *well-formed*, not that a government database issued it.
Real issuer-level verification needs an official API (e.g. DigiLocker), which can be
plugged in later by replacing `validate_document`.
"""
import re
import time

# Verhoeff checksum tables (used by Aadhaar)
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
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_valid(number):
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(number):
    """Used by tests to build valid sample numbers."""
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return _INV[c]


DOC_TYPES = {
    "aadhaar": "Aadhaar",
    "pan": "PAN card",
    "passport": "Passport",
    "driving_license": "Driving licence",
    "voter_id": "Voter ID",
}


def normalize_number(raw):
    return re.sub(r"[\s\-]", "", raw or "").upper()


def _check(name, passed, detail):
    return {"check": name, "passed": bool(passed), "detail": detail}


def validate_document(doc_type, number, holder_name):
    """Return a list of check results. All must pass for the document to be accepted."""
    checks = []
    if doc_type == "aadhaar":
        ok_fmt = bool(re.fullmatch(r"[2-9]\d{11}", number))
        checks.append(_check("format", ok_fmt, "12 digits, not starting with 0 or 1"))
        checks.append(_check("checksum", ok_fmt and verhoeff_valid(number), "Verhoeff checksum"))
    elif doc_type == "pan":
        ok_fmt = bool(re.fullmatch(r"[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]", number))
        checks.append(_check("format", ok_fmt, "AAAAA9999A with a valid holder-type letter"))
        if ok_fmt and number[3] == "P":
            surname = (holder_name.split() or [""])[-1][:1].upper()
            first = (holder_name.split() or [""])[0][:1].upper()
            checks.append(_check(
                "name_letter", number[4] in (surname, first),
                "5th character matches the holder's surname initial",
            ))
    elif doc_type == "passport":
        ok_fmt = bool(re.fullmatch(r"[A-PR-WY][1-9]\d{5}[1-9]", number))
        checks.append(_check("format", ok_fmt, "1 letter + 7 digits (Indian passport format)"))
    elif doc_type == "driving_license":
        ok_fmt = bool(re.fullmatch(r"[A-Z]{2}\d{2}(19|20)\d{2}\d{7}", number))
        year_ok = ok_fmt and 1950 <= int(number[4:8]) <= time.gmtime().tm_year
        checks.append(_check("format", ok_fmt, "State code, RTO code, year, 7-digit serial"))
        if ok_fmt:
            checks.append(_check("issue_year", year_ok, "Issue year is realistic"))
    elif doc_type == "voter_id":
        ok_fmt = bool(re.fullmatch(r"[A-Z]{3}\d{7}", number))
        checks.append(_check("format", ok_fmt, "EPIC number: 3 letters + 7 digits"))
    return checks


def names_overlap(a, b):
    """True if the two names share at least one word of 3+ letters (case-insensitive)."""
    wa = {w for w in re.findall(r"[a-z]+", a.lower()) if len(w) >= 3}
    wb = {w for w in re.findall(r"[a-z]+", b.lower()) if len(w) >= 3}
    return bool(wa & wb)
