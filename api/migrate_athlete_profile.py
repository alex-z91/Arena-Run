"""Run once before deploying the updated API against an EXISTING database.

BACK UP the database first. This migration only adds nullable columns.
For production, replace this with versioned Alembic migrations.
"""
import os
from sqlalchemy import create_engine, inspect, text

url = os.environ.get("DATABASE_URL")
if not url:
    raise SystemExit("Defina DATABASE_URL apontando para o banco correto.")
engine = create_engine(url.replace("postgres://", "postgresql://", 1))
changes = {
    "user": [("birth_date", "VARCHAR(10)"), ("city", "VARCHAR(120)")],
    "race": [("local_city", "VARCHAR(120)")],
    "registration": [("category_snapshot", "VARCHAR(60)"), ("locality_snapshot", "VARCHAR(20)")],
}
with engine.begin() as conn:
    inspector = inspect(conn)
    for table, columns in changes.items():
        if not inspector.has_table(table):
            raise RuntimeError(f"Tabela {table} não encontrada. Inicialize a API primeiro.")
        present = {x["name"] for x in inspector.get_columns(table)}
        for name, column_type in columns:
            if name not in present:
                conn.execute(text(f'ALTER TABLE "{table}" ADD COLUMN {name} {column_type}'))
                print(f"Adicionada coluna: {table}.{name}")
print("Migração concluída. Cadastros antigos devem completar perfil antes de se inscrever.")
