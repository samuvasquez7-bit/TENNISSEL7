import os
import re
import sqlite3
import threading


class SQLiteCursor(sqlite3.Cursor):
    def execute(self, sql, parameters=()):
        sql = sql.replace('%s', '?')
        sql = re.sub(r'\bNOW\(\)', 'CURRENT_TIMESTAMP', sql, flags=re.IGNORECASE)
        sql = re.sub(r'\bCURDATE\(\)', "DATE('now', 'localtime')", sql, flags=re.IGNORECASE)
        return super().execute(sql, parameters)


class SQLiteConnection(sqlite3.Connection):
    def cursor(self, factory=None, *, dictionary=False):
        cursor = super().cursor(factory or SQLiteCursor)
        if dictionary:
            cursor.row_factory = sqlite3.Row
        return cursor


_initialization_lock = threading.Lock()


def connect(database_path, schema_path):
    os.makedirs(os.path.dirname(database_path), exist_ok=True)
    connection = sqlite3.connect(
        database_path,
        timeout=10,
        factory=SQLiteConnection,
    )
    connection.execute('PRAGMA foreign_keys = ON')

    try:
        with _initialization_lock:
            has_tables = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite_%' LIMIT 1"
            ).fetchone()
            if not has_tables:
                with open(schema_path, encoding='utf-8') as schema_file:
                    connection.executescript(schema_file.read())
        return connection
    except Exception:
        connection.close()
        raise
