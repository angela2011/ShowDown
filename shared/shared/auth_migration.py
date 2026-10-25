"""Additive auth migration. Existing data stays unassigned and inaccessible."""
from sqlalchemy import inspect, text
from shared.models import Base


def require_auth_schema(connection):
    inspector = inspect(connection)
    if inspector.has_table('domains') and 'owner_id' not in {c['name'] for c in inspector.get_columns('domains')}:
        raise RuntimeError('Authentication migration required: run python -m app.migrate_auth before starting API/worker')


def migrate_auth(connection):
    if connection.dialect.name == 'postgresql':
        connection.execute(text('SELECT pg_advisory_xact_lock(726384019)'))
    elif connection.dialect.name != 'sqlite':
        raise RuntimeError('Unsupported migration database')
    Base.metadata.create_all(connection)
    inspector = inspect(connection)
    if 'owner_id' not in {c['name'] for c in inspector.get_columns('domains')}:
        kind = 'UUID' if connection.dialect.name == 'postgresql' else 'CHAR(32)'
        connection.execute(text(f'ALTER TABLE domains ADD COLUMN owner_id {kind} REFERENCES users(id)'))
    connection.execute(text('CREATE INDEX IF NOT EXISTS ix_domains_owner_id ON domains (owner_id)'))
