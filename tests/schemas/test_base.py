from __future__ import annotations

from datetime import UTC

from grc_agent.schemas.base import utc_now


def test_utc_now_is_timezone_aware() -> None:
    now = utc_now()
    assert now.tzinfo is not None
    assert now.utcoffset() == UTC.utcoffset(now)
