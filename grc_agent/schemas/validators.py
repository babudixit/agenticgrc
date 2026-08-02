"""Reusable identifier normalization/validation helpers.

Centralized here so ingesters, normalizers, and schemas all agree on what a
valid CVE/CWE/ATT&CK-technique/CPE identifier looks like, rather than each
module inventing its own regex.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_CWE_PATTERN = re.compile(r"^CWE-\d+$", re.IGNORECASE)
_ATTACK_TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)
_CPE_PREFIXES = ("cpe:2.3:", "cpe:/")


def normalize_cve_id(value: str) -> str:
    """Validate and canonicalize a CVE identifier, e.g. `cve-2021-3156` -> `CVE-2021-3156`."""
    candidate = value.strip().upper()
    if not _CVE_PATTERN.match(candidate):
        raise ValueError(f"Invalid CVE identifier: {value!r} (expected format CVE-YYYY-NNNN)")
    return candidate


def normalize_cwe_id(value: str) -> str:
    """Validate and canonicalize a CWE identifier, e.g. `cwe-79` -> `CWE-79`."""
    candidate = value.strip().upper()
    if not _CWE_PATTERN.match(candidate):
        raise ValueError(f"Invalid CWE identifier: {value!r} (expected format CWE-NNN)")
    return candidate


def normalize_attack_technique_id(value: str) -> str:
    """Validate and canonicalize a MITRE ATT&CK technique ID, e.g. `t1068` -> `T1068`."""
    candidate = value.strip().upper()
    if not _ATTACK_TECHNIQUE_PATTERN.match(candidate):
        raise ValueError(
            f"Invalid ATT&CK technique identifier: {value!r} "
            "(expected format T#### or T####.###)"
        )
    return candidate


def normalize_cpe(value: str) -> str:
    """Validate and canonicalize a CPE URI (2.2 `cpe:/...` or 2.3 `cpe:2.3:...` form)."""
    candidate = value.strip().lower()
    if not candidate.startswith(_CPE_PREFIXES):
        raise ValueError(f"Invalid CPE identifier: {value!r} (expected a cpe:2.3: or cpe:/ URI)")
    return candidate


def normalize_ip_address(value: str) -> str:
    """Validate an IPv4/IPv6 address and return its canonical string form."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {value!r}") from exc


def validate_id_list(values: Iterable[str], normalizer: Callable[[str], str]) -> list[str]:
    """Apply `normalizer` to every item, preserving order and de-duplicating."""
    seen: dict[str, None] = {}
    for raw in values:
        normalized = normalizer(raw)
        seen.setdefault(normalized, None)
    return list(seen.keys())
