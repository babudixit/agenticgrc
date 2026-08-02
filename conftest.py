"""Repository-wide pytest configuration.

Deliverable 1 intentionally ships with zero test modules (there is no logic
yet to test). By default pytest exits with code 5 ("no tests collected") in
that situation, which most CI systems treat as a failure. This hook downgrades
that specific case to a clean pass so `pytest` succeeds on an empty suite,
without masking any other exit status (real failures, errors, etc. still
propagate normally).
"""

from __future__ import annotations

import pytest


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if exitstatus == pytest.ExitCode.NO_TESTS_COLLECTED:
        session.exitstatus = pytest.ExitCode.OK
