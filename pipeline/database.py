import sqlite3
from contextlib import contextmanager

DB_FILE = "quantumtrace.db"


@contextmanager
def connect(db_path=DB_FILE):
    """Commit on success and always close; sqlite3's own context manager never closes."""
    conn = sqlite3.connect(db_path)
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_db(db_path: str = DB_FILE) -> None:
    with connect(db_path) as conn:
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS input_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                target_path TEXT,
                source_type TEXT NOT NULL,         -- "upload" ou "git_repo"
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                total_assets INTEGER DEFAULT 0,
                risk_score REAL DEFAULT 0.0
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS code_classification (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id INTEGER,
                file_path TEXT NOT NULL,
                language TEXT NOT NULL,
                primitive TEXT NOT NULL,
                risk TEXT NOT NULL,
                key_size INTEGER,
                line_number INTEGER,
                suggestion TEXT,
                code_snippet TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(source_id) REFERENCES input_sources(id)
            )
        """)


def create_source(
    name: str, target_path: str, source_type: str, db_path: str = DB_FILE
) -> int:
    init_db(db_path)
    with connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO input_sources (name, target_path, source_type) VALUES (?, ?, ?)",
            (name, target_path, source_type),
        )
        return cursor.lastrowid


def add_code_classification(classification: dict, db_path: str = DB_FILE) -> None:
    with connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO code_classification (
                source_id, file_path, language, primitive, risk, key_size, line_number, suggestion, code_snippet
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                classification.get("source_id"),
                classification.get("file_path"),
                classification.get("language"),
                classification.get("primitive"),
                classification.get("risk"),
                classification.get("key_size"),
                classification.get("line_number"),
                classification.get("suggestion"),
                classification.get("code_snippet"),
            ),
        )
