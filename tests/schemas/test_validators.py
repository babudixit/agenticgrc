from __future__ import annotations

import pytest

from grc_agent.schemas.validators import (
    normalize_attack_technique_id,
    normalize_cpe,
    normalize_cve_id,
    normalize_cwe_id,
    normalize_ip_address,
    validate_id_list,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CVE-2021-3156", "CVE-2021-3156"),
        ("cve-2021-3156", "CVE-2021-3156"),
        (" CVE-2021-44228 ", "CVE-2021-44228"),
    ],
)
def test_normalize_cve_id_valid(raw: str, expected: str) -> None:
    assert normalize_cve_id(raw) == expected


@pytest.mark.parametrize("raw", ["CVE-21-3156", "not-a-cve", "CVE-2021", ""])
def test_normalize_cve_id_invalid(raw: str) -> None:
    with pytest.raises(ValueError, match="Invalid CVE identifier"):
        normalize_cve_id(raw)


@pytest.mark.parametrize(("raw", "expected"), [("cwe-79", "CWE-79"), ("CWE-787", "CWE-787")])
def test_normalize_cwe_id_valid(raw: str, expected: str) -> None:
    assert normalize_cwe_id(raw) == expected


@pytest.mark.parametrize("raw", ["79", "CWE-", "weakness-79"])
def test_normalize_cwe_id_invalid(raw: str) -> None:
    with pytest.raises(ValueError, match="Invalid CWE identifier"):
        normalize_cwe_id(raw)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("t1068", "T1068"), ("T1068.001", "T1068.001")],
)
def test_normalize_attack_technique_id_valid(raw: str, expected: str) -> None:
    assert normalize_attack_technique_id(raw) == expected


@pytest.mark.parametrize("raw", ["1068", "TA0001", "T106"])
def test_normalize_attack_technique_id_invalid(raw: str) -> None:
    with pytest.raises(ValueError, match="Invalid ATT&CK technique identifier"):
        normalize_attack_technique_id(raw)


@pytest.mark.parametrize(
    "raw",
    ["cpe:2.3:a:openbsd:openssh:8.2", "cpe:/a:openbsd:openssh:8.2"],
)
def test_normalize_cpe_valid(raw: str) -> None:
    assert normalize_cpe(raw) == raw.lower()


def test_normalize_cpe_invalid() -> None:
    with pytest.raises(ValueError, match="Invalid CPE identifier"):
        normalize_cpe("openssh-8.2")


def test_normalize_ip_address_valid() -> None:
    assert normalize_ip_address("10.0.4.55") == "10.0.4.55"
    assert normalize_ip_address(" 2001:db8::1 ") == "2001:db8::1"


def test_normalize_ip_address_invalid() -> None:
    with pytest.raises(ValueError, match="Invalid IP address"):
        normalize_ip_address("999.999.999.999")


def test_validate_id_list_dedupes_and_preserves_order() -> None:
    result = validate_id_list(
        ["cve-2021-3156", "CVE-2021-3156", "cve-2021-44228"], normalize_cve_id
    )
    assert result == ["CVE-2021-3156", "CVE-2021-44228"]


def test_validate_id_list_propagates_normalizer_error() -> None:
    with pytest.raises(ValueError, match="Invalid CVE identifier"):
        validate_id_list(["not-a-cve"], normalize_cve_id)
