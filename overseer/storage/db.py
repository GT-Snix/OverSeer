import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from overseer.parser.schema import Advisory

DEFAULT_DB_PATH = Path("overseer.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS advisories (
    unique_id TEXT PRIMARY KEY,
    product_name TEXT NOT NULL,
    product_version TEXT NOT NULL,
    oem_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    mitigation TEXT NOT NULL,
    published_date TEXT NOT NULL,
    source_url TEXT NOT NULL,
    first_seen TEXT NOT NULL
);
"""

_connection: sqlite3.Connection | None = None


def init_db(db_path: str | Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Open (or create) the advisories database and ensure the schema exists."""
    global _connection
    _connection = sqlite3.connect(db_path, check_same_thread=False)
    _connection.execute(_SCHEMA)
    _connection.commit()
    return _connection


def _get_connection() -> sqlite3.Connection:
    if _connection is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return _connection


def is_duplicate(unique_id: str) -> bool:
    """Return True if an advisory with this unique_id is already stored."""
    conn = _get_connection()
    cursor = conn.execute("SELECT 1 FROM advisories WHERE unique_id = ?", (unique_id,))
    return cursor.fetchone() is not None


def insert_advisory(advisory: Advisory) -> None:
    """Insert a normalized advisory, stamping it with a first_seen timestamp."""
    conn = _get_connection()
    conn.execute(
        """
        INSERT INTO advisories (
            unique_id, product_name, product_version, oem_name, severity,
            description, mitigation, published_date, source_url, first_seen
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            advisory.unique_id,
            advisory.product_name,
            advisory.product_version,
            advisory.oem_name,
            advisory.severity,
            advisory.description,
            advisory.mitigation,
            advisory.published_date.isoformat(),
            str(advisory.source_url),
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()


def get_history(limit: int = 50) -> list[dict]:
    """Return the most recently seen advisories, newest first."""
    conn = _get_connection()
    cursor = conn.execute(
        "SELECT * FROM advisories ORDER BY first_seen DESC LIMIT ?", (limit,)
    )
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]
