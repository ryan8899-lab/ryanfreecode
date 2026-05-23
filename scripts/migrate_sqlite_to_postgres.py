#!/usr/bin/env python3
"""Copy WebUI runtime data from local SQLite webui.db into DATABASE_URL Postgres.

Usage:
  DATABASE_URL=postgresql://user:pass@host:5432/db \
    python scripts/migrate_sqlite_to_postgres.py --sqlite output/webui.db

By default this refuses to import into non-empty destination tables. Use --replace
to clear destination runtime tables first.
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webui.backend.db import Database, get_data_dir  # noqa: E402

TABLES = [
    "users",
    "sessions",
    "runtime_meta",
    "registered_accounts",
    "pipeline_results",
    "card_results",
    "oauth_status",
]


def rows_for(src: sqlite3.Connection, table: str) -> list[dict]:
    src.row_factory = sqlite3.Row
    return [dict(r) for r in src.execute(f"SELECT * FROM {table} ORDER BY rowid ASC").fetchall()]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sqlite", default=str(get_data_dir() / "webui.db"))
    ap.add_argument("--replace", action="store_true", help="delete destination rows before import")
    args = ap.parse_args()

    if not os.environ.get("DATABASE_URL", "").startswith(("postgres://", "postgresql://")):
        ap.error("DATABASE_URL must be a Postgres URL")

    sqlite_path = Path(args.sqlite)
    if not sqlite_path.exists():
        ap.error(f"SQLite DB not found: {sqlite_path}")

    dest = Database(Path("/unused/webui.db"))
    src = sqlite3.connect(sqlite_path)
    src.row_factory = sqlite3.Row

    with dest._conn() as c:
        existing = {t: c.execute(f"SELECT COUNT(*) AS n FROM {t}").fetchone()["n"] for t in TABLES}
        non_empty = {t: n for t, n in existing.items() if n}
        if non_empty and not args.replace:
            raise SystemExit(f"Destination is not empty: {non_empty}. Re-run with --replace if intended.")
        if args.replace:
            for table in reversed(TABLES):
                c.execute(f"DELETE FROM {table}")

        imported: dict[str, int] = {}
        for table in TABLES:
            rows = rows_for(src, table)
            imported[table] = len(rows)
            for row in rows:
                cols = list(row.keys())
                placeholders = ",".join("?" for _ in cols)
                updates = ", ".join(f"{col}=EXCLUDED.{col}" for col in cols)
                conflict = {
                    "users": "username",
                    "sessions": "id",
                    "runtime_meta": "key",
                    "oauth_status": "email",
                }.get(table)
                sql = f"INSERT INTO {table}({','.join(cols)}) VALUES ({placeholders})"
                if conflict:
                    sql += f" ON CONFLICT({conflict}) DO UPDATE SET {updates}"
                c.execute(sql, [row[col] for col in cols])

        # Keep SERIAL sequences ahead of imported explicit ids.
        for table in ("registered_accounts", "pipeline_results", "card_results"):
            c.execute(
                f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), "
                f"COALESCE((SELECT MAX(id) FROM {table}), 1), true)"
            )

    print("Imported rows:", imported)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
