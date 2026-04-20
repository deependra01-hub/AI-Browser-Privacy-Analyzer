"""Reset the local SQLite database used by the privacy analyzer."""

from __future__ import annotations

from pathlib import Path

from backend.database.db import DB_PATH


def main() -> None:
    db_path = Path(DB_PATH)
    journal_path = db_path.with_name(f"{db_path.name}-journal")

    if db_path.exists():
        db_path.unlink()
        print(f"Deleted: {db_path}")
    else:
        print(f"Database not found: {db_path}")

    if journal_path.exists():
        journal_path.unlink()
        print(f"Deleted: {journal_path}")


if __name__ == "__main__":
    main()
