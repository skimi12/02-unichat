from datetime import datetime, timedelta, timezone
import os
import secrets
import unicodedata

from flask import (
    Flask, abort, flash, redirect, render_template, request, session, url_for,
)
from flask_login import (
    LoginManager, UserMixin, current_user, login_required, login_user, logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFError, CSRFProtect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload
from werkzeug.security import check_password_hash, generate_password_hash

from database_config import database_url_for_app


# Never fall back to a shared signing key. Configure a unique random secret in
# the hosting environment before starting this application.
secret_key = os.environ.get('SECRET_KEY', '')
if len(secret_key.encode('utf-8')) < 32:
    raise RuntimeError('SECRET_KEY must contain at least 32 bytes of random secret material.')

app = Flask(__name__)
database_url = database_url_for_app(os.getenv('DATABASE_URL', 'sqlite:///data.db'), app.root_path)
app.config.update(
    SECRET_KEY=secret_key,
    SQLALCHEMY_DATABASE_URI=database_url,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    MAX_CONTENT_LENGTH=16 * 1024,
    MAX_FORM_MEMORY_SIZE=16 * 1024,
    MAX_FORM_PARTS=10,
    SESSION_COOKIE_SECURE=os.getenv('UNICHAT_INSECURE_LOCAL_HTTP') != '1',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    REMEMBER_COOKIE_SECURE=True,
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    SESSION_REFRESH_EACH_REQUEST=False,
    WTF_CSRF_TIME_LIMIT=3600,
)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.session_protection = 'strong'

# PBKDF2 fits the existing 128-character column. Existing supported hashes
# remain readable; no destructive schema migration is needed for this update.
PASSWORD_METHOD = 'pbkdf2:sha256:1000000'
DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_urlsafe(32), method=PASSWORD_METHOD)
PAGE_SIZE = 20
MAX_DATABASE_ID = (1 << 63) - 1
JST = timezone(timedelta(hours=9))


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Post', backref='author', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method=PASSWORD_METHOD)

    def check_password(self, password):
        try:
            return check_password_hash(self.password_hash or '', password)
        except (TypeError, ValueError):
            return False


class Post(db.Model):
    __tablename__ = 'posts'

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))


@login_manager.user_loader
def load_user(user_id):
    try:
        value = int(user_id)
    except (TypeError, ValueError, OverflowError):
        return None
    if not 0 < value <= MAX_DATABASE_ID:
        return None
    return db.session.get(User, value)


@app.after_request
def secure_response(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net/npm/bootstrap@5.1.0/dist/js/bootstrap.bundle.min.js; "
        "style-src 'self' https://cdn.jsdelivr.net/npm/bootstrap@5.1.0/dist/css/bootstrap.min.css; "
        "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
        "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    )
    response.headers['X-Frame-Options'] = 'DENY'
    if request.endpoint != 'static':
        response.headers['Cache-Control'] = 'private, no-store'
    return response


@app.errorhandler(CSRFError)
def csrf_error(_error):
    return render_template(
        'error.html',
        message='フォームの有効期限が切れたか、送信元を確認できませんでした。画面を開き直して送信してください。',
    ), 400


@app.errorhandler(413)
def too_large(_error):
    return render_template('error.html', message='送信内容が大きすぎます。入力を短くして再度送信してください。'), 413


def form_text(name):
    # Reject ambiguous duplicate fields instead of silently taking one value.
    values = request.form.getlist(name)
    return values[0] if len(values) == 1 else ''


def valid_username(username):
    return (
        1 <= len(username) <= 64
        and username == username.strip()
        and not any(unicodedata.category(char).startswith('C') for char in username)
    )


def page_of_posts(query):
    # An ID cursor avoids loading or counting every post and gives stable pages
    # when newer posts arrive. The feed is ordered by insertion, newest first.
    before = request.args.get('before')
    if before is not None:
        if not before.isascii() or not before.isdecimal() or len(before) > 19:
            abort(400)
        before_id = int(before)
        if not 0 < before_id <= MAX_DATABASE_ID:
            abort(400)
        query = query.filter(Post.id < before_id)
    rows = query.options(joinedload(Post.author)).order_by(Post.id.desc()).limit(PAGE_SIZE + 1).all()
    posts = rows[:PAGE_SIZE]
    return posts, posts[-1].id if len(rows) > PAGE_SIZE else None


@app.route('/')
def index():
    return redirect(url_for('timeline' if current_user.is_authenticated else 'login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('timeline'))
    if request.method == 'POST':
        username = form_text('username').strip()
        password = form_text('password')
        if not valid_username(username):
            flash('ユーザー名は1〜64文字で、制御文字を含めず入力してください。')
            return render_template('register.html'), 400
        if not 12 <= len(password) <= 128:
            flash('パスワードは12〜128文字で入力してください。')
            return render_template('register.html'), 400
        if User.query.filter_by(username=username).first():
            flash('そのユーザー名は既に使用されています。')
            return render_template('register.html'), 409
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            # The unique database constraint is authoritative if registrations
            # arrive together. Do not expose a SQL error or leave a failed txn.
            db.session.rollback()
            flash('そのユーザー名は既に使用されています。')
            return render_template('register.html'), 409
        flash('登録が完了しました！ログインしてください。')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('timeline'))
    if request.method == 'POST':
        username = form_text('username')
        password = form_text('password')
        # Legacy registration had no application-level length caps. Keep old
        # credentials usable; the 16 KiB request cap bounds parsing and hashing.
        # New registration still enforces the stricter length policy above.
        if not username or not password:
            flash('ユーザー名またはパスワードが正しくありません。')
            return render_template('login.html'), 400
        user = User.query.filter_by(username=username).first()
        if user is None:
            check_password_hash(DUMMY_PASSWORD_HASH, password)
            valid = False
        else:
            valid = user.check_password(password)
        if not valid:
            flash('ユーザー名またはパスワードが正しくありません。')
            return render_template('login.html'), 401
        session.clear()
        login_user(user)
        session.permanent = True
        return redirect(url_for('timeline'))
    return render_template('login.html')


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login'))


@app.route('/timeline')
@login_required
def timeline():
    posts, next_cursor = page_of_posts(Post.query)
    return render_template('timeline.html', posts=posts, next_cursor=next_cursor)


@app.route('/post', methods=['GET', 'POST'])
@login_required
def post():
    if request.method == 'POST':
        content = form_text('content').strip()
        if not content:
            flash('投稿内容を入力してください。')
            return render_template('post.html'), 400
        if len(content) > 140:
            flash('投稿は140文字以内にしてください。')
            return render_template('post.html'), 400
        db.session.add(Post(content=content, author=current_user))
        db.session.commit()
        flash('投稿が完了しました！')
        return redirect(url_for('timeline'))
    return render_template('post.html')


@app.route('/mypage')
@login_required
def mypage():
    posts, next_cursor = page_of_posts(Post.query.filter_by(user_id=current_user.id))
    return render_template('mypage.html', posts=posts, user=current_user, next_cursor=next_cursor)


@app.template_filter('jst')
def jst(datetime_utc):
    if datetime_utc is None:
        return ''
    if datetime_utc.tzinfo is None:
        datetime_utc = datetime_utc.replace(tzinfo=timezone.utc)
    return datetime_utc.astimezone(JST).strftime('%Y/%m/%d %H:%M')


# create_all creates missing tables only; it never deletes existing data. It is
# not a migration mechanism, and no model/schema change is made in this patch.
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run()
