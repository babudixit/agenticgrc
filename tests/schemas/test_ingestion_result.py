from __future__ import annotations

import time

from grc_agent.schemas import IngestionResult


def test_run_id_defaults_are_unique() -> None:
    a = IngestionResult(source_name="nist_sp800_53")
    b = IngestionResult(source_name="nist_sp800_53")
    assert a.run_id != b.run_id


def test_success_is_false_until_finished() -> None:
    result = IngestionResult(source_name="nist_sp800_53")
    assert result.success is False

    result.finish()
    assert result.success is True


def test_success_is_false_if_any_record_failed() -> None:
    result = IngestionResult(source_name="nist_sp800_53")
    result.record_error("could not parse control AC-99")
    result.finish()

    assert result.records_failed == 1
    assert result.success is False


def test_record_success_increments_counters() -> None:
    result = IngestionResult(source_name="nist_sp800_53")
    result.record_success(count=5)

    assert result.records_processed == 5
    assert result.records_written == 5
    assert result.records_failed == 0


def test_record_error_increments_processed_and_failed() -> None:
    result = IngestionResult(source_name="nist_sp800_53")
    result.record_error("bad record")

    assert result.records_processed == 1
    assert result.records_failed == 1
    assert result.errors == ["bad record"]


def test_duration_seconds_unset_until_finished() -> None:
    result = IngestionResult(source_name="nist_sp800_53")
    assert result.duration_seconds is None

    time.sleep(0.01)
    result.finish()

    assert result.duration_seconds is not None
    assert result.duration_seconds > 0


def test_json_dump_includes_computed_fields() -> None:
    result = IngestionResult(source_name="nist_sp800_53")
    result.record_success(count=3)
    result.finish()

    dumped = result.model_dump(mode="json")

    assert dumped["success"] is True
    assert dumped["duration_seconds"] is not None


def test_roundtrip_excluding_computed_fields() -> None:
    """Computed fields (`success`, `duration_seconds`) are output-only — they're
    derived from other fields, not part of the constructible input contract, so
    they must be excluded before validating a dumped record back into a model.
    """
    original = IngestionResult(source_name="nist_sp800_53")
    original.record_success(count=3)
    original.finish()

    dumped = original.model_dump(mode="json", exclude={"success", "duration_seconds"})
    restored = IngestionResult.model_validate(dumped)

    assert restored == original
