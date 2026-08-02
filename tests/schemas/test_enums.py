from __future__ import annotations

from grc_agent.schemas.enums import Severity


def test_severity_rank_orders_critical_highest() -> None:
    ordered = sorted(Severity, key=lambda s: s.rank)
    assert ordered == [
        Severity.INFORMATIONAL,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ]


def test_severity_values_match_fr_205_scale() -> None:
    assert {s.value for s in Severity} == {"Critical", "High", "Medium", "Low", "Informational"}
