"""Database URL compatibility and driver checks, without opening connections."""
from pathlib import Path

from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import ArgumentError, NoSuchModuleError


def database_url_for_app(value: str, root_path: str) -> URL:
    try:
        url = make_url(value)
    except (ArgumentError, TypeError, ValueError):
        raise RuntimeError('DATABASE_URL must be a valid SQLAlchemy connection URL.') from None

    # Pin the DBAPI selection instead of depending on SQLAlchemy's changing
    # default. Preserve all credentials, host, port, database and query options.
    if url.drivername in ('postgres', 'postgresql'):
        url = url.set(drivername='postgresql+psycopg')

    if url.get_backend_name() == 'postgresql':
        try:
            dialect = url.get_dialect()
            if dialect.is_async:
                raise RuntimeError('DATABASE_URL must use a synchronous PostgreSQL driver for this Flask application.')
            # Import the selected DBAPI to fail clearly when an explicitly
            # configured optional driver is absent. This does not connect.
            dialect.import_dbapi()
        except (ImportError, NoSuchModuleError):
            raise RuntimeError(
                'The PostgreSQL driver selected by DATABASE_URL is unavailable. '
                'This installation includes psycopg: use postgresql+psycopg://, '
                'or install the explicitly selected compatible driver. '
                'Explicit driver URLs are not silently rewritten.'
            ) from None

    # Flask-SQLAlchemy 3 moved relative SQLite files under instance_path. Keep
    # the original root-relative location so an upgrade opens the existing DB.
    if url.get_backend_name() == 'sqlite' and url.database not in (None, '', ':memory:'):
        path = Path(url.database)
        if not path.is_absolute():
            url = url.set(database=str(Path(root_path) / path))
    return url
