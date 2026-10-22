"""Source-scoped SQLite storage, retaining the complete scanner evidence."""
import json
import os
import shutil
import sqlite3
from contextlib import contextmanager

from pipeline.database import init_db
from pipeline.registry import load_scanners

# kind -> {"table", "schema", "columns", "legacy"}. Extension modules register their own kind.
STORAGE = {}


def register_storage(kind, table, schema, columns, legacy):
    """schema: CREATE TABLE SQL (None if init_db creates it); columns(component) -> {column: value};
    legacy(row) -> component, for rows saved before full component JSON was kept."""
    STORAGE[kind] = {"table": table, "schema": schema, "columns": columns, "legacy": legacy}


class SourceStore:
    def __init__(self, path):
        self.path = str(path)
        load_scanners()  # Imports extension modules so their storage is registered.
        init_db(self.path)
        with self.connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS analysis_source (
                    id TEXT PRIMARY KEY, client_id TEXT UNIQUE, name TEXT NOT NULL,
                    kind TEXT NOT NULL, url TEXT, files_json TEXT NOT NULL DEFAULT '[]',
                    status TEXT NOT NULL, error TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS source_report (
                    source_id TEXT NOT NULL REFERENCES analysis_source(id),
                    kind TEXT NOT NULL, header_json TEXT NOT NULL,
                    PRIMARY KEY (source_id, kind)
                );
            """)
            for storage in STORAGE.values():
                if storage["schema"]:
                    conn.execute(storage["schema"])
            tables = {kind: storage["table"] for kind, storage in STORAGE.items()}
            for table in tables.values():
                columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
                for column in ("source_id", "component_json"):
                    if column not in columns:
                        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} TEXT")
                conn.execute(f"CREATE INDEX IF NOT EXISTS {table}_source ON {table}(source_id)")
            # Keep rows created by the original database helpers visible.
            if any(conn.execute(f"SELECT 1 FROM {table} WHERE source_id IS NULL LIMIT 1").fetchone() for table in tables.values()):
                conn.execute("INSERT OR IGNORE INTO analysis_source(id,name,kind,status) VALUES('legacy','Existing database','database','ready')")
                for kind, table in tables.items():
                    conn.execute(f"UPDATE {table} SET source_id='legacy' WHERE source_id IS NULL")
                    conn.execute("INSERT OR IGNORE INTO source_report VALUES('legacy', ?, '{}')", (kind,))
            conn.execute("UPDATE analysis_source SET status='failed', error='Analysis was interrupted by a server restart. Retry this source.' WHERE status IN ('pending','processing')")

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=15)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def create(self, source):
        with self.connect() as conn:
            conn.execute("""INSERT INTO analysis_source(id,client_id,name,kind,url,files_json,status)
                VALUES(?,?,?,?,?,?,?)""", (source["id"], source.get("clientSourceId"), source["name"], source["kind"],
                                          source.get("url"), json.dumps(source.get("files", [])), source.get("status", "pending")))

    def find_client(self, client_id):
        with self.connect() as conn:
            row = conn.execute("SELECT id FROM analysis_source WHERE client_id=?", (client_id,)).fetchone()
        return self.get(row[0]) if row else None

    def list(self):
        with self.connect() as conn:
            return [self.describe(row) for row in conn.execute("SELECT * FROM analysis_source ORDER BY created_at, rowid")]

    @staticmethod
    def describe(row):
        return {"id": row["id"], "name": row["name"], "kind": row["kind"], "url": row["url"],
                "files": json.loads(row["files_json"]), "status": row["status"], "error": row["error"],
                "createdAt": row["created_at"]}

    def get(self, source_id):
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM analysis_source WHERE id=?", (source_id,)).fetchone()
            if row is None:
                return None
            source = self.describe(row)
            if source["status"] == "ready":
                source["reports"] = {}
                for report in conn.execute("SELECT * FROM source_report WHERE source_id=?", (source_id,)):
                    kind = report["kind"]
                    storage = STORAGE.get(kind)
                    if storage is None:
                        continue  # Saved by a build with an extension this build does not have.
                    header = json.loads(report["header_json"])
                    header["components"] = [json.loads(r["component_json"]) if r["component_json"] else storage["legacy"](r)
                                            for r in conn.execute(f"SELECT * FROM {storage['table']} WHERE source_id=? ORDER BY id", (source_id,))]
                    source["reports"][kind] = header
            return source

    def status(self, source_id, status, error=None):
        with self.connect() as conn:
            conn.execute("UPDATE analysis_source SET status=?,error=? WHERE id=?", (status, error, source_id))

    def save_reports(self, source_id, reports):
        unknown = sorted(set(reports) - set(STORAGE))
        if unknown:
            raise ValueError(f"No storage registered for report kind(s): {', '.join(unknown)}")
        with self.connect() as conn:
            for storage in STORAGE.values():
                table = storage["table"]
                conn.execute(f"DELETE FROM {table} WHERE source_id=?", (source_id,))
            conn.execute("DELETE FROM source_report WHERE source_id=?", (source_id,))
            for kind, report in reports.items():
                conn.execute("INSERT INTO source_report VALUES(?,?,?)", (source_id, kind, json.dumps({k: v for k, v in report.items() if k != "components"})))
                for component in report["components"]:
                    values = STORAGE[kind]["columns"](component)
                    values.update(source_id=source_id, component_json=json.dumps(component))
                    conn.execute(f"INSERT INTO {STORAGE[kind]['table']} ({','.join(values)}) VALUES ({','.join('?' for _ in values)})", tuple(values.values()))
            conn.execute("UPDATE analysis_source SET status='ready',error=NULL WHERE id=?", (source_id,))

    def delete(self, source_id, base_dir="input_files"):
        """Apaga a source da BD e limpa a sua pasta física em input_files/"""
        with self.connect() as conn:
            for storage in STORAGE.values():
                conn.execute(f"DELETE FROM {storage['table']} WHERE source_id=?", (source_id,))
            conn.execute("DELETE FROM source_report WHERE source_id=?", (source_id,))
            conn.execute("DELETE FROM analysis_source WHERE id=?", (source_id,))

        # Remove a pasta associada no disco se existir
        if os.path.exists(base_dir):
            for entry in os.listdir(base_dir):
                if entry.startswith(f"source_{source_id}"):
                    target = os.path.join(base_dir, entry)
                    if os.path.isdir(target):
                        shutil.rmtree(target, ignore_errors=True)
                    elif os.path.isfile(target):
                        os.remove(target)

    def reset_all(self, base_dir="input_files"):
        """Limpa toda a base de dados e a pasta input_files para reiniciar o ambiente."""
        with self.connect() as conn:
            for storage in STORAGE.values():
                conn.execute(f"DELETE FROM {storage['table']}")
            conn.execute("DELETE FROM source_report")
            conn.execute("DELETE FROM analysis_source")

        if os.path.exists(base_dir):
            for item in os.listdir(base_dir):
                item_path = os.path.join(base_dir, item)
                if item != ".gitkeep":
                    if os.path.isdir(item_path):
                        shutil.rmtree(item_path, ignore_errors=True)
                    elif os.path.isfile(item_path):
                        os.remove(item_path)


def code_columns(component):
    props = component.get("cryptoProperties", {})
    assessment = component.get("quantumRiskAssessment", {})
    return {"file_path": component.get("source") or "Not recorded", "language": props.get("language") or "Unknown",
            "primitive": props.get("detectedAlgorithm") or "Unknown",
            "risk": assessment.get("tier") or "UNKNOWN", "key_size": props.get("keySizeBits", props.get("keySize")), "line_number": component.get("line"),
            "suggestion": assessment.get("suggestion") or assessment.get("reason"), "code_snippet": component.get("codeSnippet")}


def code_legacy_component(row):
    return {"type": "application-code", "name": f"{row['file_path']}:{row['line_number']}", "source": row["file_path"],
            "line": row["line_number"], "codeSnippet": row["code_snippet"],
            "cryptoProperties": {"language": row["language"], "detectedAlgorithm": row["primitive"], "keySize": row["key_size"]},
            "quantumRiskAssessment": {"tier": row["risk"], "reason": row["suggestion"]}}


# init_db creates code_classification, so code needs no schema of its own.
register_storage("code", "code_classification", None, code_columns, code_legacy_component)
