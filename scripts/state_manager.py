"""SQLite state persistence for processed intelligence items."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator


class StateManager:
    """Manage deduplication state in a local SQLite database."""

    def __init__(self, db_path: str | Path = Path("data") / "agent_state.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_database()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.db_path)
        try:
            yield connection
        finally:
            connection.close()

    def _initialize_database(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS processed_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            processed_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_processed_title ON processed_items (title);
        """

        try:
            with self._connection() as connection:
                connection.executescript(schema)
                connection.commit()
        except sqlite3.Error as error:
            raise RuntimeError(f"Failed to initialize database at {self.db_path}: {error}") from error

    def reset_database(self) -> None:
        """Delete all stored state while keeping the database file."""

        statement = "DELETE FROM processed_items;"
        try:
            with self._connection() as connection:
                connection.execute(statement)
                connection.commit()
        except sqlite3.Error as error:
            raise RuntimeError(f"Failed to reset database at {self.db_path}: {error}") from error

    def is_processed(self, url: str, title: str) -> bool:
        """Return True when URL or title already exists in state."""

        query = """
        SELECT 1
        FROM processed_items
        WHERE url = ? OR title = ?
        LIMIT 1;
        """

        try:
            with self._connection() as connection:
                cursor = connection.execute(query, (url, title))
                return cursor.fetchone() is not None
        except sqlite3.Error as error:
            raise RuntimeError(f"Failed to check processed state for {url!r}: {error}") from error

    def mark_as_processed(self, url: str, title: str) -> None:
        """Store an item as processed using UTC ISO timestamp."""

        statement = """
        INSERT INTO processed_items (url, title, processed_at)
        VALUES (?, ?, ?);
        """
        processed_at = datetime.now(timezone.utc).isoformat()

        try:
            with self._connection() as connection:
                connection.execute(statement, (url, title, processed_at))
                connection.commit()
        except sqlite3.IntegrityError as error:
            raise ValueError(f"Item already exists for url={url!r}") from error
        except sqlite3.Error as error:
            raise RuntimeError(f"Failed to persist processed state for {url!r}: {error}") from error

    def get_stats(self) -> dict[str, int | str]:
        """Return current database statistics for logging and diagnostics."""

        count_query = "SELECT COUNT(*) FROM processed_items;"
        try:
            with self._connection() as connection:
                row = connection.execute(count_query).fetchone()
                total_processed = int(row[0]) if row and row[0] is not None else 0
        except sqlite3.Error as error:
            raise RuntimeError(f"Failed to read state statistics: {error}") from error

        return {
            "database_path": str(self.db_path),
            "total_processed": total_processed,
        }