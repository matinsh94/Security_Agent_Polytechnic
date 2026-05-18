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
        """Initialize production-grade CTI database schema with all tables."""
        
        schema = """
        -- Processed articles tracking
        CREATE TABLE IF NOT EXISTS processed_articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            source TEXT NOT NULL,
            processed_at TEXT NOT NULL
        );

        -- Extracted vulnerabilities
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT UNIQUE,
            cvss_base_score REAL,
            cvss_vector TEXT,
            description TEXT,
            published_date TEXT,
            nist_severity TEXT,
            source TEXT,
            discovered_at TEXT NOT NULL
        );

        -- Indicators of Compromise
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_type TEXT NOT NULL,
            value TEXT NOT NULL,
            source_article_id INTEGER,
            confidence_score REAL DEFAULT 0.8,
            extracted_at TEXT NOT NULL,
            FOREIGN KEY(source_article_id) REFERENCES processed_articles(id),
            UNIQUE(ioc_type, value)
        );

        -- Threat analysis results
        CREATE TABLE IF NOT EXISTS threat_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            article_id INTEGER NOT NULL,
            cve_id TEXT,
            threat_score INTEGER,
            severity TEXT,
            attack_vector TEXT,
            affected_assets TEXT,
            remediation_en TEXT,
            remediation_fa TEXT,
            analyzed_at TEXT NOT NULL,
            FOREIGN KEY(article_id) REFERENCES processed_articles(id)
        );

        -- MITRE ATT&CK mappings
        CREATE TABLE IF NOT EXISTS mitre_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            tactic TEXT,
            technique_id TEXT,
            technique_name TEXT,
            mapped_at TEXT NOT NULL
        );

        -- Malware campaign tracking
        CREATE TABLE IF NOT EXISTS malware_campaigns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_name TEXT UNIQUE,
            description TEXT,
            first_seen TEXT,
            last_seen TEXT,
            ioc_ids TEXT,
            severity TEXT
        );

        -- Historical context storage
        CREATE TABLE IF NOT EXISTS historical_context (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reference_key TEXT UNIQUE,
            context_data TEXT,
            source TEXT,
            stored_at TEXT NOT NULL
        );

        -- Create indexes for performance
        CREATE INDEX IF NOT EXISTS idx_processed_articles_url ON processed_articles(url);
        CREATE INDEX IF NOT EXISTS idx_processed_articles_title ON processed_articles(title);
        CREATE INDEX IF NOT EXISTS idx_processed_articles_source ON processed_articles(source);
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve ON vulnerabilities(cve_id);
        CREATE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs(ioc_type, value);
        CREATE INDEX IF NOT EXISTS idx_threat_analysis_cve ON threat_analysis(cve_id);
        CREATE INDEX IF NOT EXISTS idx_mitre_mappings_cve ON mitre_mappings(cve_id);
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

    def store_vulnerability(self, cve_id: str, cvss_score: float = 0.0, severity: str = "", description: str = "") -> None:
        """Store a CVE vulnerability record."""
        statement = """
        INSERT OR IGNORE INTO vulnerabilities (cve_id, cvss_base_score, nist_severity, description, source, discovered_at)
        VALUES (?, ?, ?, ?, ?, ?);
        """
        discovered_at = datetime.now(timezone.utc).isoformat()
        try:
            with self._connection() as connection:
                connection.execute(statement, (cve_id, cvss_score, severity, description, "cti-agent", discovered_at))
                connection.commit()
        except sqlite3.Error as error:
            raise RuntimeError(f"Failed to store vulnerability {cve_id}: {error}") from error

    def store_ioc(self, ioc_type: str, value: str, source_article_id: int | None = None, confidence: float = 0.8) -> None:
        """Store an IOC (Indicator of Compromise)."""
        statement = """
        INSERT OR IGNORE INTO iocs (ioc_type, value, source_article_id, confidence_score, extracted_at)
        VALUES (?, ?, ?, ?, ?);
        """
        extracted_at = datetime.now(timezone.utc).isoformat()
        try:
            with self._connection() as connection:
                connection.execute(statement, (ioc_type, value, source_article_id, confidence, extracted_at))
                connection.commit()
        except sqlite3.Error as error:
            raise RuntimeError(f"Failed to store IOC {ioc_type}:{value}: {error}") from error

    def store_threat_analysis(self, article_id: int, cve_id: str | None, threat_score: int, severity: str, 
                             remediation_en: str = "", remediation_fa: str = "") -> None:
        """Store threat analysis results."""
        statement = """
        INSERT INTO threat_analysis (article_id, cve_id, threat_score, severity, remediation_en, remediation_fa, analyzed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?);
        """
        analyzed_at = datetime.now(timezone.utc).isoformat()
        try:
            with self._connection() as connection:
                connection.execute(statement, (article_id, cve_id, threat_score, severity, remediation_en, remediation_fa, analyzed_at))
                connection.commit()
        except sqlite3.Error as error:
            raise RuntimeError(f"Failed to store threat analysis for article {article_id}: {error}") from error

    def store_mitre_mapping(self, cve_id: str, tactic: str, technique_id: str, technique_name: str) -> None:
        """Store MITRE ATT&CK mapping."""
        statement = """
        INSERT INTO mitre_mappings (cve_id, tactic, technique_id, technique_name, mapped_at)
        VALUES (?, ?, ?, ?, ?);
        """
        mapped_at = datetime.now(timezone.utc).isoformat()
        try:
            with self._connection() as connection:
                connection.execute(statement, (cve_id, tactic, technique_id, technique_name, mapped_at))
                connection.commit()
        except sqlite3.Error as error:
            raise RuntimeError(f"Failed to store MITRE mapping for {cve_id}: {error}") from error

    def get_iocs_by_type(self, ioc_type: str) -> list[dict]:
        """Retrieve all IOCs of a specific type."""
        query = "SELECT * FROM iocs WHERE ioc_type = ? ORDER BY extracted_at DESC;"
        try:
            with self._connection() as connection:
                cursor = connection.execute(query, (ioc_type,))
                return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as error:
            raise RuntimeError(f"Failed to retrieve IOCs of type {ioc_type}: {error}") from error

    def get_threat_analysis_by_cve(self, cve_id: str) -> dict | None:
        """Retrieve threat analysis for a specific CVE."""
        query = "SELECT * FROM threat_analysis WHERE cve_id = ? ORDER BY analyzed_at DESC LIMIT 1;"
        try:
            with self._connection() as connection:
                cursor = connection.execute(query, (cve_id,))
                row = cursor.fetchone()
                return dict(row) if row else None
        except sqlite3.Error as error:
            raise RuntimeError(f"Failed to retrieve threat analysis for {cve_id}: {error}") from error