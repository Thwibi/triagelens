"""Candidate regexes and the small pattern tables they need (spec 05 section 3).

The regexes are copied from the spec verbatim. They only *find* candidates;
:mod:`app.ioc.validate` decides whether a candidate is a real indicator. Keeping
detection and validation apart is what lets the spec's validator rules change
without touching the scanners.

None of these patterns uses nested quantifiers over overlapping alternatives, so
matching is linear in the length of the text; the timing test in the suite holds
that to a one-second cap on a 1 MB adversarial string.
"""

from __future__ import annotations

import re

#: Candidate scanners, in the order the extractor applies them.
IPV4 = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?![\d.])"
)
IPV6 = re.compile(r"(?<![:\w])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![:\w])")
URL = re.compile(r"\b(?:https?|ftps?|sftp|tftp|ldaps?|smb)://[^\s<>\"'`\\^{}|]+", re.IGNORECASE)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,24}\b")
DOMAIN = re.compile(
    r"(?<![\w@.\-/])(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,24}|xn--[a-z0-9\-]{2,59})(?![\w\-])",
    re.IGNORECASE,
)
MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
WINPATH = re.compile(r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*")
UNCPATH = re.compile(r"\\\\[A-Za-z0-9._$\-]+\\[^\s\"<>|]+")
NIXPATH = re.compile(
    r"(?<![\w:/.])(?:/(?:tmp|var/tmp|dev/shm|home|root|etc|usr/local|opt|var/www)"
    r"(?:/[^\s\"'<>|;&]+)+)"
)
REGKEY = re.compile(r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\[^\r\n\"']+")

#: Domain-ish file extensions that must not be mistaken for a TLD.
FILENAME_EXTENSIONS: frozenset[str] = frozenset(
    {
        "exe",
        "dll",
        "sys",
        "log",
        "tmp",
        "dat",
        "txt",
        "ini",
        "cfg",
        "json",
        "xml",
        "yml",
        "yaml",
    }
)

#: TLDs that are also common file extensions or words. Accepted only from a
#: structured field or when at least two labels precede them (spec 05 section 3).
AMBIGUOUS_TLDS: frozenset[str] = frozenset(
    {
        "sh",
        "py",
        "pl",
        "rs",
        "zip",
        "mov",
        "md",
        "so",
        "cc",
        "ps",
        "pm",
        "am",
        "ai",
        "io",
        "cs",
        "ad",
    }
)

#: A MAC address, which the IPv6 scanner otherwise loves.
MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", re.IGNORECASE)

#: A clock time, ``12:34:56``, likewise IPv6-shaped.
CLOCK = re.compile(r"\d{1,2}:\d{2}:\d{2}")

#: A field name that precedes a hex id rather than a file hash. Matches
#: ``sid = ``/``sid=``/``guid: ``/``uuid = `` and a bare ``sid`` at the end of
#: the prefix window, so ``sid = <hex>`` is never treated as a file hash.
ID_CONTEXT = re.compile(r"(?:sid|guid|uuid|id)\s*(?:[=:]\s*)?$", re.IGNORECASE)

#: Leading-zero octet, invalid in an IPv4 address.
LEADING_ZERO = re.compile(r"(?:^|\.)0\d")

#: ``UNCPATH`` keeps its spec name; this alias reads better in code that avoids a
#: bare acronym.
UNC_PATH = UNCPATH

__all__ = [
    "AMBIGUOUS_TLDS",
    "CLOCK",
    "CVE",
    "DOMAIN",
    "EMAIL",
    "FILENAME_EXTENSIONS",
    "ID_CONTEXT",
    "IPV4",
    "IPV6",
    "LEADING_ZERO",
    "MAC",
    "MD5",
    "NIXPATH",
    "REGKEY",
    "SHA1",
    "SHA256",
    "UNC_PATH",
    "URL",
    "WINPATH",
]
