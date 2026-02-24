"""
Alembic migration environment for ReconScope.

Supports **async** migrations via ``asyncpg`` and auto-imports all ORM models
so that ``--autogenerate`` can detect schema changes.

Usage::

    # Generate a new migration after model changes
    alembic revision --autogenerate -m "describe change"

    # Apply all pending migrations
    alembic upgrade head

    # Rollback one migration
    alembic downgrade -1
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from app.config import get_settings

# Import Base and all models so that Base.metadata contains every table.
from app.core.database import Base
from app.models import (  # noqa: F401 – imported for side-effects
    AttackPath,
    Correlation,
    CVEMatch,
    Finding,
    Scan,
    ScanStatus,
    Service,
    Subdomain,
    Target,
    Technology,
)

# ── Alembic Config object ────────────────────────────────────────────────────
config = context.config

# Interpret the config file for Python logging if present.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Metadata used by --autogenerate to detect changes.
target_metadata = Base.metadata

# Inject the database URL from application settings into the alembic config
# so that we have a single source of truth.
settings = get_settings()
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)


# ── Offline migrations (emit SQL without a live database) ────────────────────

def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    Configures the context with just a URL and not an Engine.  Calls to
    ``context.execute()`` emit the given SQL string to the script output.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


# ── Online migrations (connect to a live database) ───────────────────────────

def do_run_migrations(connection: Connection) -> None:
    """Execute migrations inside an already-established connection."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Create an async engine and run migrations within its connection.

    Uses ``asyncpg`` under the hood so that the migration environment matches
    the async driver used by the application at runtime.
    """
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    Delegates to the async migration runner which creates an ``AsyncEngine``
    and runs the actual migration steps synchronously inside the connection.
    """
    asyncio.run(run_async_migrations())


# ── Entry point ──────────────────────────────────────────────────────────────

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
