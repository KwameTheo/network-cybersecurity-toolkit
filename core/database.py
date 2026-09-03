"""
SQLite Database Storage Manager
Persists diagnostic reports, security baseline scans, and troubleshooting history
locally in 'data/toolkit.db' with zero server configuration.
"""

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger()

# Database directory and file path
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_FILE = DATA_DIR / "toolkit.db"


def get_db_connection() -> sqlite3.Connection:
    """Returns a connection to the local SQLite database."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_FILE))
    conn.row_factory = sqlite3.Row  # Return dict-like rows
    return conn


def init_db():
    """Initializes the database schema if tables do not exist."""
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    report_type TEXT NOT NULL,
                    host_name TEXT NOT NULL,
                    os_edition TEXT NOT NULL,
                    summary_text TEXT NOT NULL,
                    score_percent REAL,
                    json_data TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_reports_timestamp 
                ON audit_reports(timestamp DESC)
            """)
        logger.info("SQLite database schema initialized successfully.")
    except Exception as e:
        logger.error(f"Error initializing SQLite database: {e}", exc_info=True)
    finally:
        conn.close()


def save_report(
    report_type: str,
    host_name: str,
    os_edition: str,
    summary_text: str,
    full_report_dict: Dict[str, Any],
    score_percent: Optional[float] = None
) -> int:
    """
    Saves a diagnostic report snapshot to the SQLite database.
    Returns the inserted report ID.
    """
    init_db()
    conn = get_db_connection()
    timestamp = full_report_dict.get("timestamp") or full_report_dict.get("metadata", {}).get("generated_at", "")
    json_str = json.dumps(full_report_dict, indent=2)

    try:
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO audit_reports (
                    timestamp, report_type, host_name, os_edition, summary_text, score_percent, json_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (timestamp, report_type, host_name, os_edition, summary_text, score_percent, json_str)
            )
            report_id = cursor.lastrowid
        logger.info(f"Saved audit report #{report_id} ({report_type}) to SQLite DB.")
        return report_id
    except Exception as e:
        logger.error(f"Failed to save report to SQLite: {e}", exc_info=True)
        return -1
    finally:
        conn.close()


def get_recent_reports(limit: int = 25) -> List[Dict[str, Any]]:
    """Retrieves the most recent audit reports from database."""
    init_db()
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            """
            SELECT id, timestamp, report_type, host_name, os_edition, summary_text, score_percent
            FROM audit_reports
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        )
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"Failed to fetch recent reports: {e}")
        return []
    finally:
        conn.close()


def get_report_by_id(report_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves a single full report by its database ID."""
    init_db()
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "SELECT * FROM audit_reports WHERE id = ?",
            (report_id,)
        )
        row = cursor.fetchone()
        if row:
            res = dict(row)
            try:
                res["parsed_data"] = json.loads(res["json_data"])
            except Exception:
                res["parsed_data"] = {}
            return res
        return None
    except Exception as e:
        logger.error(f"Failed to fetch report #{report_id}: {e}")
        return None
    finally:
        conn.close()


def delete_report(report_id: int) -> bool:
    """Deletes a report by ID."""
    init_db()
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("DELETE FROM audit_reports WHERE id = ?", (report_id,))
        logger.info(f"Deleted report #{report_id} from SQLite DB.")
        return True
    except Exception as e:
        logger.error(f"Failed to delete report #{report_id}: {e}")
        return False
    finally:
        conn.close()
