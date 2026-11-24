"""Local-only regression checks. Every database used here is in memory."""
import os
import re
import secrets
import sqlite3
import tempfile
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

# Override inherited host settings before importing the application. Tests never
# connect to a deployment's database or use its signing key.
os.environ['SECRET_KEY'] = secrets.token_hex(32)
os.environ['DATABASE_URL'] = 'sqlite://'
os.environ.pop('UNICHAT_INSECURE_LOCAL_HTTP', None)

from app import app, db, User, Post, load_user
from sqlalchemy.exc import IntegrityError
from werkzeug.datastructures import MultiDict
from werkzeug.security import generate_password_hash

ORIGIN = 'https://localhost'
PASSWORD = 'local-test-password-123'


class SecurityTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
        self.context = app.app_context()
        self.context.push()
        self.assertEqual(db.engine.url.get_backend_name(), 'sqlite')
        self.assertIn(db.engine.url.database, (None, '', ':memory:'))
        db.drop_all()
        db.create_all()
        self.client = app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.context.pop()

    def get(self, path, client=None):
        with app.app_context():
            return (client or self.client).get(path, base_url=ORIGIN)

    def token(self, path='/login', client=None):
        response = self.get(path, client=client)
        self.assertEqual(response.status_code, 200)
        match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        self.assertIsNotNone(match)
        return match.group(1).decode()

    def post(self, path, data, token=None, client=None, referer=None):
        values = MultiDict(data)
        if token is not None:
            values.add('csrf_token', token)
        with app.app_context():
            return (client or self.client).post(
                path, data=values, base_url=ORIGIN,
                headers={'Referer': referer or ORIGIN + path},
            )

    def create_user(self, username='member', password=PASSWORD):
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return user

    def login(self, username='member', password=PASSWORD):
        token = self.token()
        response = self.post('/login', {'username': username, 'password': password}, token)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith('/timeline'))
        return response

    def test_missing_or_short_signing_key_stops_startup(self):
        for value in (None, 'too-short'):
            env = dict(os.environ)
            if value is None:
                env.pop('SECRET_KEY', None)
            else:
                env['SECRET_KEY'] = value
            result = subprocess.run(
                [sys.executable, '-c', 'import app'], env=env,
                cwd=Path(__file__).resolve().parents[1], capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'SECRET_KEY must contain at least 32 bytes', result.stderr)

    def test_legacy_relative_sqlite_path_preserves_existing_rows(self):
        with tempfile.TemporaryDirectory(prefix='unichat-db-test-') as directory:
            root = Path(directory)
            for filename in ('app.py', 'database_config.py'):
                shutil.copyfile(Path(__file__).resolve().parents[1] / filename, root / filename)
            connection = sqlite3.connect(root / 'data.db')
            connection.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username VARCHAR(64) UNIQUE, password_hash VARCHAR(128))')
            connection.execute('INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)', (42, 'existing-member', 'unused-test-value'))
            connection.commit()
            connection.close()
            env = dict(os.environ)
            env.pop('DATABASE_URL', None)
            result = subprocess.run(
                [sys.executable, '-c', "from app import app, db, User; context = app.app_context(); context.push(); assert db.session.get(User, 42).username == 'existing-member'; assert not __import__('pathlib').Path('instance/data.db').exists()"],
                cwd=root, env=env, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_every_mutation_rejects_missing_csrf(self):
        for path in ('/register', '/login', '/post', '/logout'):
            with self.subTest(path=path):
                self.assertEqual(self.post(path, {}).status_code, 400)
        self.assertEqual(User.query.count(), 0)
        self.assertEqual(Post.query.count(), 0)

    def test_bad_or_other_session_csrf_is_rejected(self):
        first_token = self.token('/register')
        other_client = app.test_client()
        other_token = self.token('/register', client=other_client)
        for token in ('invalid', other_token):
            response = self.post('/register', {'username': 'member', 'password': PASSWORD}, token)
            self.assertEqual(response.status_code, 400)
        self.assertNotEqual(first_token, other_token)
        self.assertEqual(User.query.count(), 0)

    def test_https_cross_origin_form_is_rejected(self):
        token = self.token('/register')
        response = self.post('/register', {'username': 'member', 'password': PASSWORD}, token,
                             referer='https://unrelated.example/form')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(User.query.count(), 0)

    def test_registration_stores_hash_and_duplicate_is_handled(self):
        token = self.token('/register')
        data = {'username': 'member', 'password': PASSWORD}
        self.assertEqual(self.post('/register', data, token).status_code, 302)
        user = User.query.one()
        self.assertNotEqual(user.password_hash, PASSWORD)
        self.assertLessEqual(len(user.password_hash), 128)
        self.assertTrue(user.check_password(PASSWORD))
        self.assertEqual(self.post('/register', data, token).status_code, 409)
        self.assertEqual(User.query.count(), 1)

    def test_registration_validates_bounded_inputs(self):
        token = self.token('/register')
        cases = [
            {'username': '', 'password': PASSWORD},
            {'username': 'a' * 65, 'password': PASSWORD},
            {'username': 'name\x00', 'password': PASSWORD},
            {'username': 'member', 'password': 'a' * 11},
            {'username': 'member', 'password': 'a' * 129},
            {'username': 'member'},
        ]
        for data in cases:
            self.assertEqual(self.post('/register', data, token).status_code, 400)
        self.assertEqual(User.query.count(), 0)

    def test_duplicate_fields_are_not_ambiguous(self):
        token = self.token('/register')
        response = self.post('/register', MultiDict([
            ('username', 'one'), ('username', 'two'), ('password', PASSWORD),
        ]), token)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(User.query.count(), 0)

    def test_unique_constraint_conflict_rolls_back_cleanly(self):
        token = self.token('/register')
        with patch.object(db.session, 'commit', side_effect=IntegrityError('insert', {}, Exception())):
            response = self.post('/register', {'username': 'member', 'password': PASSWORD}, token)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(User.query.count(), 0)

    def test_login_supports_existing_short_passwords(self):
        self.create_user(password='old-pass')
        self.login(password='old-pass')
        self.assertEqual(self.get('/timeline').status_code, 200)

    def test_legacy_werkzeug_hash_and_long_credentials_still_log_in(self):
        # The old SQLite application did not enforce declared varchar lengths.
        username = 'legacy-name-' * 7
        password = 'legacy-password-' * 12
        self.assertGreater(len(username), 64)
        self.assertGreater(len(password), 128)
        user = User(username=username, password_hash=generate_password_hash(
            password, method='pbkdf2:sha256:260000',
        ))
        db.session.add(user)
        db.session.commit()
        self.login(username=username, password=password)
        self.assertEqual(self.get('/timeline').status_code, 200)

    def test_login_rejects_missing_oversized_and_wrong_credentials(self):
        self.create_user()
        token = self.token()
        for data in ({}, {'username': 'member', 'password': ''}):
            self.assertEqual(self.post('/login', data, token).status_code, 400)
        self.assertEqual(self.post('/login', {'username': 'member', 'password': 'x' * 20_000}, token).status_code, 413)
        for username in ('member', 'unknown'):
            response = self.post('/login', {'username': username, 'password': 'wrong'}, token)
            self.assertEqual(response.status_code, 401)
        self.assertEqual(self.get('/timeline').status_code, 302)

    def test_login_rotates_csrf_session(self):
        self.create_user()
        old_token = self.token()
        self.assertEqual(self.post('/login', {'username': 'member', 'password': PASSWORD}, old_token).status_code, 302)
        new_token = self.token('/post')
        self.assertNotEqual(old_token, new_token)
        self.assertEqual(self.post('/post', {'content': 'old form'}, old_token).status_code, 400)
        self.assertEqual(self.post('/post', {'content': 'new form'}, new_token).status_code, 302)

    def test_logout_requires_post_and_valid_csrf(self):
        self.create_user()
        self.login()
        self.assertEqual(self.get('/logout').status_code, 405)
        self.assertEqual(self.get('/timeline').status_code, 200)
        self.assertEqual(self.post('/logout', {}).status_code, 400)
        token = self.token('/post')
        self.assertEqual(self.post('/logout', {}, token).status_code, 302)
        self.assertEqual(self.get('/timeline').status_code, 302)

    def test_anonymous_user_cannot_post(self):
        token = self.token()
        self.assertEqual(self.post('/post', {'content': 'no session'}, token).status_code, 302)
        self.assertEqual(Post.query.count(), 0)

    def test_posts_use_session_owner_and_escape_markup(self):
        user = self.create_user()
        another = self.create_user('another')
        self.login()
        token = self.token('/post')
        content = '<img src=x onerror="alert(1)">'
        response = self.post('/post', {'content': content, 'user_id': str(another.id)}, token)
        self.assertEqual(response.status_code, 302)
        record = Post.query.one()
        self.assertEqual(record.user_id, user.id)
        page = self.get('/timeline')
        self.assertIn(b'&lt;img', page.data)
        self.assertNotIn(content.encode(), page.data)

    def test_post_content_and_total_body_are_bounded(self):
        self.create_user()
        self.login()
        token = self.token('/post')
        for content in (' ', 'x' * 141):
            self.assertEqual(self.post('/post', {'content': content}, token).status_code, 400)
        self.assertEqual(self.post('/post', {'content': 'x' * 20_000}, token).status_code, 413)
        self.assertEqual(Post.query.count(), 0)

    def test_timeline_is_paginated_and_mypage_stays_scoped(self):
        user = self.create_user()
        another = self.create_user('another')
        for index in range(25):
            db.session.add(Post(content=f'Own post {index}', author=user))
        db.session.add(Post(content='Another member post', author=another))
        db.session.commit()
        self.login()
        first = self.get('/timeline')
        self.assertEqual(first.data.count(b'class="post-card"'), 20)
        match = re.search(rb'href="/timeline\?before=(\d+)"', first.data)
        self.assertIsNotNone(match)
        second = self.get('/timeline?before=' + match.group(1).decode())
        self.assertEqual(second.data.count(b'class="post-card"'), 6)
        own = self.get('/mypage')
        self.assertEqual(own.data.count(b'class="post-card"'), 20)
        self.assertNotIn(b'Another member post', own.data)
        for cursor in ('-1', '0', 'x', '9' * 40):
            self.assertEqual(self.get('/timeline?before=' + cursor).status_code, 400)

    def test_sessions_and_html_have_security_headers(self):
        self.create_user()
        response = self.login()
        cookie = response.headers['Set-Cookie']
        for flag in ('Secure', 'HttpOnly', 'SameSite=Lax'):
            self.assertIn(flag, cookie)
        page = self.get('/post')
        self.assertEqual(page.headers['Cache-Control'], 'private, no-store')
        self.assertEqual(page.headers['X-Content-Type-Options'], 'nosniff')
        self.assertIn("form-action 'self'", page.headers['Content-Security-Policy'])
        self.assertIn("frame-ancestors 'none'", page.headers['Content-Security-Policy'])
        self.assertNotIn(b'<script>', page.data)

    def test_invalid_user_ids_fail_closed(self):
        for value in ('not-a-number', '-1', '9' * 50, None):
            self.assertIsNone(load_user(value))


if __name__ == '__main__':
    unittest.main()
