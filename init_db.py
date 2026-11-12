"""Initialize the SQLite database from schema.sql."""
import sqlite3
from pathlib import Path

DB_PATH = "app.db"
SCHEMA = "schema.sql"


def init():
    with open(SCHEMA) as f:
        sql = f.read()
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(sql)
    conn.commit()
    conn.close()
    # Make sure storage/ exists
    Path("storage").mkdir(exist_ok=True)
    print(f"Database initialized at {DB_PATH}")
    print(f"Storage folder ready at ./storage/")


if __name__ == "__main__":
    init()
