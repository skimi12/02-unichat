# UniChat - 大学サークル向けミニTwitter風アプリ

大学のサークルやゼミなど、小規模コミュニティで使う投稿アプリです。登録・ログイン、140文字までの投稿、タイムライン、自分の投稿一覧を提供します。

## 技術構成

Python 3.10以上、Flask、Flask-SQLAlchemy、Flask-Login、Flask-WTF、SQLite／PostgreSQL（psycopg）、Jinja2、Bootstrap。動作確認した依存バージョンは `requirements.txt` に固定しています。

## 開発環境

```sh
git clone https://github.com/skimi12/02-unichat.git
cd 02-unichat
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Windowsでは仮想環境の有効化に `.venv\Scripts\activate` を使用します。

**起動前に `SECRET_KEY` の設定が必要です。** 32バイト以上の予測できない秘密値を、ホスティングの環境変数／秘密管理機能で設定してください。ソースコードやGitHubに保存しないでください。設定がない場合や短すぎる場合は、安全のため起動を拒否します。全ワーカーで同じ値を使い、再起動のたびに作り直さないでください。

ローカル開発の例です。下記は秘密値を画面に表示せず、現在のシェルの環境変数へ入れます。開発用の値を本番に流用しないでください。

```sh
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export UNICHAT_INSECURE_LOCAL_HTTP=1
flask --app app run --host 127.0.0.1
```

`UNICHAT_INSECURE_LOCAL_HTTP=1` は、開発用HTTPでセッションCookieを使うための明示的な例外です。本番では設定せず、HTTPSで配信してください。通常はCookieにSecure、HttpOnly、SameSite=Laxを付けます。

## 既存サービスへ反映する場合

- 既存DBをバックアップし、`DATABASE_URL` が従来のデータベースを指していることを確認してください。相対SQLite URLは、旧版と同じくアプリのルートから解決します。未設定時はルートの `data.db` を使います。Flask-SQLAlchemy 3の既定変更によって空の `instance/data.db` を開かないようにしています。
- `SECRET_KEY` が未設定だった場合、以前の共通fallbackは使用できません。新しい秘密値を設定してから再起動します。漏れた可能性のあるキーを再利用しないでください。キーを交換すると以前のログインCookieとフォームは無効になり、再ログインが必要になります。
- PostgreSQL用に `psycopg[binary]==3.3.9` を同梱しています。`postgres://` とドライバー未指定の `postgresql://` は `postgresql+psycopg://` に正規化し、ユーザー名・パスワード・ホスト・DB名・SSL等のクエリ設定は保持します。既存の `postgresql+psycopg2://` などの明示ドライバーは勝手に変更しません。そのドライバーを別途導入している場合は保持し、未導入なら秘密値を含まない設定エラーで停止します。非同期ドライバーはこの同期Flaskアプリでは受け付けません。
- 依存関係を `requirements.txt` に更新します。モデルのテーブル／カラムは変更しておらず、ユーザーや投稿を削除するマイグレーションはありません。既存の対応済みパスワードハッシュは引き続き照合できます。
- ログアウトはGETリンクから、CSRFトークン付きPOSTフォームに変わります。外部クライアントがある場合も、新しいフォームと同じ保護を維持してください。
- HTTPS終端をプロキシで行う場合、WSGIへのscheme／host転送をその環境の仕様で確認してください。未検証の転送ヘッダーを無条件に信頼する設定は追加していません。

`Procfile` の `gunicorn app:app` は引き続き使用できます。

## 今回の安全性改善

- Flask-WTFのCSRF保護を登録・ログイン・投稿・ログアウトに適用。トークンは1時間有効で、ログイン／ログアウト時にセッションを更新します。
- 登録ユーザー名は1〜64文字、登録パスワードは12〜128文字。ログインには新規登録の文字数上限を適用せず、リクエスト全体16KiBの範囲内で既存の短い／長い認証情報を受け付けます。重複登録のDB競合は安全にロールバックします。
- 投稿はサーバー側でも140文字に制限。空白だけの投稿、重複した入力フィールド、16KiBを超える本文を拒否します。
- タイムラインとマイページは新しい投稿順に20件ずつ表示。マイページの対象はログイン中の本人です。
- セッションCookie、非キャッシュ、MIME誤認防止、埋め込み制限、CSPを追加。投稿の文字数カウンターを外部JSファイルに移し、インラインスクリプトを不要にしました。
- 未知のユーザー名でもパスワード照合相当の処理を行い、ログインエラーの表現を統一しています。これはログイン頻度制限の代わりではありません。

## ローカル回帰テスト

```sh
python -m unittest discover -s tests -v
python -m pip check
```

テストは独立したメモリSQLiteとランダムなテスト用秘密鍵を使い、本番DBや実アカウントへ接続しません。CSRF拒否、正常登録／ログイン、Cookie属性、所有者維持、出力エスケープ、上限、ページング、重複登録、キー設定、旧SQLiteパス互換を検証します。旧Werkzeug相当の`pbkdf2:sha256:260000`保存ハッシュと128文字超の既存パスワードによるログインも確認しています。他のすべての旧ハッシュ方式や、16KiBを超える認証情報の互換を保証するものではありません。

PostgreSQLについてはURL正規化、設定値の保持、明示ドライバー不足時のエラー、psycopgのDBAPIロードとSQLAlchemyエンジン生成を、ネットワーク接続せず確認しています。**PostgreSQL本番への接続・読み書き・TLS・既存データ移行は未検証です。**

## 確認できていない範囲

この変更は侵害の有無や脆弱性ゼロを保証するものではありません。本番ホスティング設定、実ブラウザー、複数ワーカー、既存PostgreSQLなどでの確認は別途必要です。現時点では共有ストレージを使ったログイン試行制限、招待制／所属確認、アカウント復旧や強制失効、投稿の通報・削除運用は未実装です。全登録ユーザーの投稿を全ログインユーザーが閲覧できるという既存の製品仕様も維持しています。

## 実装時に参照した公式資料

- [Flask-WTF: CSRF Protection](https://flask-wtf.readthedocs.io/en/latest/csrf/)
- [Flask: Security Considerations](https://flask.palletsprojects.com/en/stable/web-security/)
- [Flask: Configuration Handling](https://flask.palletsprojects.com/en/stable/config/)
- [Flask-SQLAlchemy: Configuration](https://flask-sqlalchemy.palletsprojects.com/en/stable/config/)
- [SQLAlchemy 2.1: Driver changes](https://docs.sqlalchemy.org/en/21/changelog/migration_21.html)
- [Psycopg: Installation](https://www.psycopg.org/psycopg3/docs/basic/install.html)

## ライセンス

[MIT License](LICENSE)
