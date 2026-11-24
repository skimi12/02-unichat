"""PostgreSQL setup checks without credentials, DNS or database connections."""
import unittest
from unittest.mock import patch

import psycopg
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import psycopg2
from sqlalchemy.engine import make_url

from database_config import database_url_for_app


class DatabaseConfigurationTests(unittest.TestCase):
    def test_malformed_url_error_does_not_include_supplied_value(self):
        with self.assertRaisesRegex(RuntimeError, 'valid SQLAlchemy connection URL') as error:
            database_url_for_app('invalid-config-local-test-value', '/tmp/unichat')
        self.assertNotIn('local-test-value', str(error.exception))

    def test_postgres_aliases_select_packaged_driver_and_keep_options(self):
        for prefix in ('postgres', 'postgresql'):
            original = make_url(prefix + '://fixture:local-only@db.invalid:5432/unichat?sslmode=require&connect_timeout=5')
            result = database_url_for_app(original.render_as_string(hide_password=False), '/tmp/unichat')
            self.assertEqual(result, original.set(drivername='postgresql+psycopg'))

    def test_explicit_supported_driver_is_preserved(self):
        original = make_url('postgresql+psycopg://fixture:local-only@db.invalid/unichat?sslmode=require')
        self.assertEqual(database_url_for_app(original.render_as_string(hide_password=False), '/tmp/unichat'), original)

    def test_engine_and_dbapi_load_without_connecting(self):
        with patch.object(psycopg, 'connect', side_effect=AssertionError('Tests must not open a database connection')) as connect:
            for prefix in ('postgres', 'postgresql', 'postgresql+psycopg'):
                url = database_url_for_app(prefix + '://fixture:local-only@db.invalid/unichat', '/tmp/unichat')
                engine = create_engine(url)
                self.assertEqual(engine.dialect.driver, 'psycopg')
                self.assertIs(engine.dialect.dbapi, psycopg)
                engine.dispose()
            connect.assert_not_called()

    def test_missing_explicit_driver_has_clear_error_without_url(self):
        # Simulate an absent optional driver independently of host packages.
        with patch.object(psycopg2.PGDialect_psycopg2, 'import_dbapi', side_effect=ModuleNotFoundError('optional DBAPI unavailable')):
            with self.assertRaisesRegex(RuntimeError, 'Explicit driver URLs are not silently rewritten') as error:
                database_url_for_app('postgresql+psycopg2://fixture:local-only@db.invalid/unichat', '/tmp/unichat')
        self.assertNotIn('local-only', str(error.exception))
        self.assertNotIn('db.invalid', str(error.exception))

    def test_installed_explicit_optional_driver_remains_selected(self):
        # Optional sync drivers remain the caller's choice when installed.
        with patch.object(psycopg2.PGDialect_psycopg2, 'import_dbapi', return_value=object()):
            original = 'postgresql+psycopg2://fixture:local-only@db.invalid/unichat'
            self.assertEqual(database_url_for_app(original, '/tmp/unichat'), make_url(original))

    def test_async_driver_is_explicitly_rejected_for_sync_app(self):
        with self.assertRaisesRegex(RuntimeError, 'synchronous PostgreSQL driver'):
            database_url_for_app('postgresql+psycopg_async://fixture:local-only@db.invalid/unichat', '/tmp/unichat')


if __name__ == '__main__':
    unittest.main()
