import sqlite3
from datetime import datetime, timezone

import pytest

from overseer.parser.schema import Advisory
from overseer.storage import db


@pytest.fixture(autouse=True)
def in_memory_db():
    db.init_db(":memory:")
    yield


def make_advisory(unique_id="ACME-2026-0001", **overrides):
    fields = dict(
        product_name="Widget Firmware",
        oem_name="Acme Corp",
        severity="Critical",
        unique_id=unique_id,
        description="Buffer overflow in network stack.",
        published_date=datetime(2026, 9, 18, tzinfo=timezone.utc),
        source_url="https://acme.example.com/advisories/0001",
    )
    fields.update(overrides)
    return Advisory(**fields)


def test_insert_and_is_duplicate():
    advisory = make_advisory()
    assert db.is_duplicate(advisory.unique_id) is False

    db.insert_advisory(advisory)

    assert db.is_duplicate(advisory.unique_id) is True
    assert db.is_duplicate("SOME-OTHER-ID") is False


def test_insert_duplicate_unique_id_raises():
    advisory = make_advisory()
    db.insert_advisory(advisory)

    with pytest.raises(sqlite3.IntegrityError):
        db.insert_advisory(advisory)


def test_get_history_returns_inserted_rows_with_first_seen():
    db.insert_advisory(make_advisory(unique_id="ACME-2026-0001"))
    db.insert_advisory(make_advisory(unique_id="ACME-2026-0002"))

    history = db.get_history(limit=10)

    assert len(history) == 2
    unique_ids = {row["unique_id"] for row in history}
    assert unique_ids == {"ACME-2026-0001", "ACME-2026-0002"}
    assert all("first_seen" in row for row in history)


def test_get_history_respects_limit():
    for i in range(5):
        db.insert_advisory(make_advisory(unique_id=f"ACME-2026-{i:04d}"))

    history = db.get_history(limit=2)

    assert len(history) == 2
