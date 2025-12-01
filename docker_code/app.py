#!/usr/bin/env python3
"""
Sample Flask API Application.
This file contains several security issues for demonstration purposes.
"""

import os
import subprocess

from flask import Flask, request, jsonify
import psycopg2

app = Flask(__name__)

# Issue 1: Hardcoded database credentials
DB_HOST = "database"
DB_USER = "admin"
DB_PASSWORD = "admin123"
DB_NAME = "production_db"

# Issue 2: Debug mode enabled in production
app.debug = True

# Issue 3: Secret key hardcoded
app.secret_key = "mysupersecretkey12345"


def get_db_connection():
    """Get database connection with hardcoded credentials."""
    return psycopg2.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        dbname=DB_NAME
    )


@app.route("/api/users/<user_id>")
def get_user(user_id):
    """Get user by ID - vulnerable to SQL injection."""
    conn = get_db_connection()
    cursor = conn.cursor()
    # Issue 4: SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return jsonify(result)


@app.route("/api/search")
def search():
    """Search endpoint - vulnerable to SQL injection."""
    query = request.args.get("q", "")
    conn = get_db_connection()
    cursor = conn.cursor()
    # Issue 5: Another SQL Injection vulnerability
    sql = f"SELECT * FROM products WHERE name LIKE '%{query}%'"
    cursor.execute(sql)
    results = cursor.fetchall()
    conn.close()
    return jsonify(results)


@app.route("/api/execute", methods=["POST"])
def execute_command():
    """Execute system command - command injection vulnerability."""
    data = request.get_json()
    command = data.get("command", "")
    # Issue 6: Command injection vulnerability
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return jsonify({"output": result.stdout, "error": result.stderr})


@app.route("/api/file")
def read_file():
    """Read file - path traversal vulnerability."""
    filename = request.args.get("name", "")
    # Issue 7: Path traversal vulnerability
    filepath = f"/app/data/{filename}"
    with open(filepath, "r") as f:
        content = f.read()
    return jsonify({"content": content})


@app.route("/api/login", methods=["POST"])
def login():
    """Login endpoint with weak authentication."""
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")
    
    # Issue 8: Weak password comparison (timing attack vulnerable)
    # Issue 9: No rate limiting
    # Issue 10: No password hashing
    if username == "admin" and password == "admin123":
        return jsonify({"status": "success", "token": "static-token-12345"})
    return jsonify({"status": "failed"}), 401


@app.route("/api/debug")
def debug_info():
    """Debug endpoint exposing sensitive information."""
    # Issue 11: Exposing sensitive environment variables
    return jsonify({
        "env": dict(os.environ),
        "db_password": DB_PASSWORD,
        "secret_key": app.secret_key
    })


if __name__ == "__main__":
    # Issue 12: Binding to all interfaces
    app.run(host="0.0.0.0", port=5000)
