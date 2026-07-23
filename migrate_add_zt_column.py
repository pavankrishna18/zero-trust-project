"""
migrate_add_zt_column.py
Adds the Session.last_zt_check column to an existing SQLite database
without losing any existing data. Run once:

    python migrate_add_zt_column.py
"""
import sqlite3
import os
import glob

# Find the sqlite db file(s) the app uses (adjust path if yours lives elsewhere)
candidates = glob.glob("*.db") + glob.glob("instance/*.db")

if not candidates:
    print("No .db file found in current directory or ./instance — "
          "edit DB_PATH below and re-run.")
    DB_PATH = None
else:
    DB_PATH = candidates[0]
    print(f"Found database: {DB_PATH}")

if DB_PATH and os.path.exists(DB_PATH):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(sessions)")
    cols = [row[1] for row in cur.fetchall()]

    if "last_zt_check" in cols:
        print("Column already exists — nothing to do.")
    else:
        cur.execute("ALTER TABLE sessions ADD COLUMN last_zt_check DATETIME")
        conn.commit()
        print("✅ Added sessions.last_zt_check column.")

    conn.close()
else:
    print("Database file not found — nothing migrated.")
