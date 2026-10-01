"""
database.py
-----------
All raw SQLite plumbing lives here so app.py never opens a connection
directly. Centralizing this makes two security properties easy to guarantee:

  1. Every query goes through sqlite3's parameterized (?) placeholders,
     because that's the only pattern used throughout this file - no query
     anywhere in this project is built with string formatting/f-strings,
     which is what prevents SQL injection.
  2. Foreign keys and row access are configured once, consistently, instead
     of being forgotten on some connections.
"""

import sqlite3
from flask import g, current_app
from werkzeug.security import generate_password_hash


def get_db():
    """
    Returns the SQLite connection for the CURRENT request.

    Flask's `g` object is request-scoped, so this opens at most one
    connection per request (the first time it's called) and reuses it for
    every subsequent call within that same request - avoiding the overhead
    and file-handle churn of reopening the DB on every query.

    `row_factory = sqlite3.Row` lets query results be read like dicts
    (row["username"]) instead of positional tuples (row[2]), which makes
    template code far less error-prone.
    """
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        # SQLite disables FK enforcement by default for backwards
        # compatibility - we turn it on explicitly so the FOREIGN KEY
        # constraints in schema.sql actually do something.
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    """
    Closes the request's DB connection when the request ends.
    Registered with app.teardown_appcontext(close_db) in app.py, so Flask
    calls this automatically - nothing else in the codebase needs to
    remember to close the connection.
    """
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app):
    """
    Creates all tables (if they don't already exist) by executing schema.sql.
    Safe to run every time the app starts - CREATE TABLE IF NOT EXISTS means
    existing data is never wiped.
    """
    with app.app_context():
        db = get_db()
        with app.open_resource("schema.sql") as f:
            db.executescript(f.read().decode("utf8"))
        db.commit()


def seed_super_admin(app, username="superadmin", email="superadmin@abuyogcc.edu.ph", password="ChangeMe!123"):
    """
    Creates ONE super_admin account if none exists yet, so the system is
    usable immediately after a fresh install (there'd otherwise be no way
    to log in and create the first admin).

    The password is hashed with werkzeug's generate_password_hash BEFORE
    it ever touches the database - the plaintext password never gets
    written to disk. Prints the credentials once to the console so the
    operator can log in and change them immediately.
    """
    with app.app_context():
        db = get_db()
        existing = db.execute(
            "SELECT id FROM users WHERE role = 'super_admin' LIMIT 1"
        ).fetchone()
        if existing:
            return  # a super admin already exists - never create a second silently

        db.execute(
            """INSERT INTO users (username, email, password_hash, full_name, role)
               VALUES (?, ?, ?, ?, 'super_admin')""",
            (username, email, generate_password_hash(password), "System Super Administrator"),
        )
        db.commit()
        print("=" * 60)
        print(" Default Super Admin created:")
        print(f"   username: {username}")
        print(f"   password: {password}")
        print(" CHANGE THIS PASSWORD IMMEDIATELY AFTER FIRST LOGIN.")
        print("=" * 60)
