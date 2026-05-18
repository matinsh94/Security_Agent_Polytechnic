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
        connection.row_factory = sqlite3.Row
        try:
            yield connection
        finally:
            connection.close()

    def _initialize_database(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS processed_articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            source TEXT NOT NULL,
            processed_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_processed_articles_title ON processed_articles (title);
        CREATE INDEX IF NOT EXISTS idx_processed_articles_source ON processed_articles (source);
        """

        try:
            with self._connection() as connection:
                connection.executescript(schema)
                connection.commit()
        except sqlite3.Error as error:
            raise RuntimeError(f"Failed to initialize database at {self.db_path}: {error}") from error

    def reset_database(self) -> None:
        """Delete all stored state while keeping the database file."""

        try:
            with self._connection() as connection:
                connection.execute("DELETE FROM processed_articles;")
                connection.commit()
        except sqlite3.Error as error:
            raise RuntimeError(f"Failed to reset database at {self.db_path}: {error}") from error

    def is_processed(self, url: str, title: str) -> bool:
        """Return True when URL or title already exists in state."""

        query = """
        SELECT 1
        FROM processed_articles
        WHERE url = ? OR title = ?
        LIMIT 1;
        """

        try:
            with self._connection() as connection:
                cursor = connection.execute(query, (url, title))
                return cursor.fetchone() is not None
        except sqlite3.Error as error:
            raise RuntimeError(f"Failed to check processed state for {url!r}: {error}") from error

    def mark_as_processed(self, url: str, title: str, source: str = "") -> None:
        """Store an item as processed using UTC ISO timestamp."""

        statement = """
        INSERT INTO processed_articles (url, title, source, processed_at)
        VALUES (?, ?, ?, ?);
        """
        processed_at = datetime.now(timezone.utc).isoformat()

        try:
            with self._connection() as connection:
                connection.execute(statement, (url, title, source, processed_at))
                connection.commit()
        except sqlite3.IntegrityError as error:
            raise ValueError(f"Item already exists for url={url!r}") from error
        except sqlite3.Error as error:
            raise RuntimeError(f"Failed to persist processed state for {url!r}: {error}") from error

    def get_stats(self) -> dict[str, int | str]:
        """Return current database statistics for logging and diagnostics."""

        total_query = "SELECT COUNT(*) AS total FROM processed_articles;"
        latest_query = "SELECT MAX(processed_at) AS latest FROM processed_articles;"
        try:
            with self._connection() as connection:
                total_row = connection.execute(total_query).fetchone()
                latest_row = connection.execute(latest_query).fetchone()
                total_processed = int(total_row["total"]) if total_row and total_row["total"] is not None else 0
                latest_processed_at = str(latest_row["latest"]) if latest_row and latest_row["latest"] else ""
        except sqlite3.Error as error:
            raise RuntimeError(f"Failed to read state statistics: {error}") from error

        return {
            "database_path": str(self.db_path),
            "total_processed": total_processed,
            "latest_processed_at": latest_processed_at,
        }