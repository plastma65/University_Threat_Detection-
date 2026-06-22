from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine


def ensure_soc_lite_schema_compatibility(engine: Engine) -> None:
    with engine.begin() as connection:
        inspector = inspect(connection)
        tables = set(inspector.get_table_names())
        if "alerts" not in tables:
            return

        existing_columns = {column["name"] for column in inspector.get_columns("alerts")}
        dialect = connection.dialect.name

        column_definitions = {
            "status": "status VARCHAR(32) DEFAULT 'open'",
            "assigned_to": "assigned_to VARCHAR(64)",
            "triage_note": "triage_note VARCHAR(1000)",
            "updated_at": "updated_at TIMESTAMP WITH TIME ZONE" if dialect == "postgresql" else "updated_at DATETIME",
        }

        for column_name, ddl in column_definitions.items():
            if column_name not in existing_columns:
                connection.execute(text(f"ALTER TABLE alerts ADD COLUMN {ddl}"))

        connection.execute(text("UPDATE alerts SET status = COALESCE(status, 'open')"))
        connection.execute(
            text("UPDATE alerts SET updated_at = COALESCE(updated_at, created_at, timestamp)")
        )
