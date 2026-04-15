import os
import json
import uuid
import bcrypt
import psycopg2
import psycopg2.extras
from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__, static_folder='.')

DB_URL = os.environ.get('DATABASE_URL')

def get_conn():
    if not DB_URL:
        raise RuntimeError('DATABASE_URL is not configured.')
    return psycopg2.connect(DB_URL)

def init_db():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS user_data (
                    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                    data_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    token UUID PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            cur.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id)')
        conn.commit()

def get_user_by_token(token):
    if not token:
        return None
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                'SELECT u.id, u.username FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = %s',
                (token,)
            )
            return cur.fetchone()

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/logo.png')
def logo():
    return send_from_directory('.', 'logo.png')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    if not username or not password:
        return jsonify({'ok': False, 'error': 'Username and password required.'}), 400
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    'INSERT INTO users (username, password_hash) VALUES (%s, %s) RETURNING id',
                    (username.lower(), password_hash)
                )
                user_id = cur.fetchone()[0]
                cur.execute(
                    'INSERT INTO user_data (user_id, data_json) VALUES (%s, %s)',
                    (user_id, json.dumps({}))
                )
                token = str(uuid.uuid4())
                cur.execute(
                    'INSERT INTO sessions (token, user_id) VALUES (%s, %s)',
                    (token, user_id)
                )
            conn.commit()
        return jsonify({'ok': True, 'token': token, 'username': username.lower()})
    except psycopg2.errors.UniqueViolation:
        return jsonify({'ok': False, 'error': 'Username already taken.'}), 409
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip().lower()
    password = data.get('password') or ''
    try:
        with get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute('SELECT id, username, password_hash FROM users WHERE username = %s', (username,))
                user = cur.fetchone()
                if not user or not bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
                    return jsonify({'ok': False, 'error': 'Invalid username or password.'}), 401
                token = str(uuid.uuid4())
                cur.execute('INSERT INTO sessions (token, user_id) VALUES (%s, %s)', (token, user['id']))
            conn.commit()
        return jsonify({'ok': True, 'token': token, 'username': user['username']})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token:
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute('DELETE FROM sessions WHERE token = %s', (token,))
                conn.commit()
        except Exception:
            pass
    return jsonify({'ok': True})

@app.route('/api/data', methods=['GET'])
def get_data():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user = get_user_by_token(token)
    if not user:
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    try:
        with get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute('SELECT data_json FROM user_data WHERE user_id = %s', (user['id'],))
                row = cur.fetchone()
                data = row['data_json'] if row else {}
        return jsonify({'ok': True, 'data': data})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/api/data', methods=['POST'])
def save_data():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user = get_user_by_token(token)
    if not user:
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    body = request.get_json() or {}
    data = body.get('data', {})
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    '''INSERT INTO user_data (user_id, data_json, updated_at)
                       VALUES (%s, %s, NOW())
                       ON CONFLICT (user_id) DO UPDATE SET data_json = EXCLUDED.data_json, updated_at = NOW()''',
                    (user['id'], json.dumps(data))
                )
            conn.commit()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)
