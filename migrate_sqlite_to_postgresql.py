import os
import sqlite3
import psycopg
from psycopg import sql

SQLITE_DB = "hardware_inventory.db"
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set.")

sqlite_conn = sqlite3.connect(SQLITE_DB)
sqlite_conn.row_factory = sqlite3.Row

pg_conn = psycopg.connect(DATABASE_URL)
pg_conn.autocommit = False

try:
    pg_cur = pg_conn.cursor()
    sqlite_cur = sqlite_conn.cursor()

    # PostgreSQL table definitions matching the ACTUAL SQLite database.
    table_definitions = {
        "users": [
            "id BIGINT PRIMARY KEY",
            "username TEXT UNIQUE NOT NULL",
            "email TEXT NOT NULL",
            "password_hash TEXT NOT NULL",
            "role TEXT NOT NULL DEFAULT 'user'",
        ],

        "hardware": [
            "item_id BIGINT PRIMARY KEY",
            "item_name TEXT NOT NULL",
            "category TEXT NOT NULL",
            "quantity INTEGER NOT NULL",
            "unit_price DOUBLE PRECISION NOT NULL",
            "status TEXT NOT NULL",
            "equipment_status TEXT NOT NULL DEFAULT 'Available'",
        ],

        "borrowings": [
            "borrowing_id BIGINT PRIMARY KEY",
            "item_id BIGINT NOT NULL",
            "user_id BIGINT NOT NULL",
            "quantity INTEGER NOT NULL",
            "start_datetime TEXT NOT NULL",
            "end_datetime TEXT NOT NULL",
            "status TEXT NOT NULL DEFAULT 'Pending Approval'",
            "deducted INTEGER DEFAULT 0",
            "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP",
        ],

        "saved_items": [
            "saved_id BIGINT PRIMARY KEY",
            "user_id BIGINT NOT NULL",
            "item_id BIGINT NOT NULL",
        ],

        "kits": [
            "kit_id BIGINT PRIMARY KEY",
            "user_id BIGINT NOT NULL",
            "kit_name TEXT NOT NULL",
            "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP",
        ],

        "kit_items": [
            "kit_item_id BIGINT PRIMARY KEY",
            "kit_id BIGINT NOT NULL",
            "item_id BIGINT NOT NULL",
            "quantity INTEGER NOT NULL DEFAULT 1",
        ],
    }

    # Create PostgreSQL tables.
    for table_name, columns in table_definitions.items():
        column_sql = sql.SQL(", ").join(
            sql.SQL(column) for column in columns
        )

        create_sql = sql.SQL(
            "CREATE TABLE IF NOT EXISTS {} ({})"
        ).format(
            sql.Identifier(table_name),
            column_sql
        )

        pg_cur.execute(create_sql)

    counts = {}

    # Migrate each table.
    for table_name in table_definitions:

        pg_cur.execute(
            sql.SQL("SELECT COUNT(*) FROM {}").format(
                sql.Identifier(table_name)
            )
        )

        destination_count = pg_cur.fetchone()[0]

        if destination_count > 0:
            raise RuntimeError(
                f"Destination table '{table_name}' is not empty."
            )

        # Read from SQLite.
        sqlite_cur.execute(
            f"SELECT * FROM {table_name}"
        )

        rows = sqlite_cur.fetchall()
        counts[table_name] = len(rows)

        if not rows:
            continue

        source_columns = [
            description[0]
            for description in sqlite_cur.description
        ]

        column_identifiers = sql.SQL(", ").join(
            sql.Identifier(column)
            for column in source_columns
        )

        placeholders = sql.SQL(", ").join(
            sql.Placeholder()
            for _ in source_columns
        )

        insert_sql = sql.SQL(
            "INSERT INTO {} ({}) VALUES ({})"
        ).format(
            sql.Identifier(table_name),
            column_identifiers,
            placeholders
        )

        for row in rows:
            values = [
                row[column]
                for column in source_columns
            ]

            pg_cur.execute(
                insert_sql,
                values
            )

    pg_conn.commit()

    print("Migration completed successfully.")
    print(f"  users:        {counts['users']}")
    print(f"  hardware:     {counts['hardware']}")
    print(f"  borrowings:   {counts['borrowings']}")
    print(f"  saved_items:  {counts['saved_items']}")
    print(f"  kits:         {counts['kits']}")
    print(f"  kit_items:    {counts['kit_items']}")

except Exception:
    pg_conn.rollback()
    raise

finally:
    sqlite_conn.close()
    pg_conn.close()