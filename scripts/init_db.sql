-- Postgres extensions needed by the schema.
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Table creation is normally handled by SQLAlchemy (Base.metadata.create_all)
-- on API startup for this starter project. If you'd rather manage schema
-- via migrations, wire up Alembic and move the DDL here instead.
