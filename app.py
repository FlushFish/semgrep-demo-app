"""
Semgrep Demo App - Intentionally Vulnerable Flask Application
DO NOT deploy this in production. This contains deliberate security flaws.
"""

import os
import pickle
import base64
import sqlite3
from flask import Flask, request, jsonify, redirect

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded password / secret
# Semgrep rule: python.lang.security.audit.hardcoded-password
DATABASE_PASSWORD = "SuperSecret123!"
API_SECRET_KEY = "sk-live-abc123def456ghi789"
ADMIN_PASSWORD = "admin123"


def get_db_connection():
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def index():
    return "Welcome to the Semgrep Demo App!"


@app.route("/user", methods=["GET"])
def get_user():
    """
    VULNERABILITY 2: SQL Injection via string concatenation
    Semgrep rule: python.lang.security.audit.formatted-sql-query
    """
    username = request.args.get("username", "")
    conn = get_db_connection()
    # BAD: String concatenation in SQL query — classic SQL injection
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    result = conn.execute(query)
    user = result.fetchone()
    conn.close()
    if user:
        return jsonify(dict(user))
    return jsonify({"error": "User not found"}), 404


@app.route("/search", methods=["GET"])
def search_users():
    """
    Another SQL injection variant using f-string formatting.
    """
    search_term = request.args.get("q", "")
    conn = get_db_connection()
    # BAD: f-string in SQL query
    query = f"SELECT * FROM users WHERE name LIKE '%{search_term}%'"
    results = conn.execute(query).fetchall()
    conn.close()
    return jsonify([dict(row) for row in results])


@app.route("/ping", methods=["POST"])
def ping_host():
    """
    VULNERABILITY 3: OS Command Injection
    Semgrep rule: python.lang.security.audit.dangerous-system-call
    """
    hostname = request.form.get("hostname", "")
    # BAD: Passing user input directly to os.system
    os.system("ping -c 3 " + hostname)
    return jsonify({"status": "ping sent", "target": hostname})


@app.route("/execute", methods=["POST"])
def execute_command():
    """
    Another command injection variant using subprocess with shell=True.
    """
    cmd = request.form.get("command", "")
    # BAD: shell=True with user input
    import subprocess
    output = subprocess.call(cmd, shell=True)
    return jsonify({"output": str(output)})


@app.route("/load-session", methods=["POST"])
def load_session():
    """
    VULNERABILITY 4: Insecure Deserialization
    Semgrep rule: python.lang.security.deserialization.avoid-pickle
    """
    session_data = request.form.get("session", "")
    # BAD: Deserializing untrusted user input with pickle
    decoded = base64.b64decode(session_data)
    user_session = pickle.loads(decoded)
    return jsonify({"session": str(user_session)})


@app.route("/deserialize", methods=["POST"])
def deserialize_object():
    """
    Another pickle deserialization variant.
    """
    raw_data = request.get_data()
    # BAD: pickle.loads on raw request data
    obj = pickle.loads(raw_data)
    return jsonify({"object_type": str(type(obj))})


@app.route("/redirect", methods=["GET"])
def open_redirect():
    """
    BONUS: Open redirect vulnerability.
    """
    url = request.args.get("url", "/")
    # BAD: Unvalidated redirect
    return redirect(url)


# VULNERABILITY 5: Debug mode enabled in production
# Semgrep rule: python.flask.security.audit.debug-enabled
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
