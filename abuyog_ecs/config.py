"""
config.py
---------
Central configuration for the Abuyog Community College Enrollment System.

Why a separate config file:
  - Keeps secrets (SECRET_KEY) out of app.py and out of version control if
    you later swap the os.environ defaults for a proper .env / secrets manager.
  - All security-relevant cookie flags live in ONE place, so they can't be
    forgotten on a route-by-route basis.
"""

import os


class Config:
    # SECRET_KEY signs the session cookie. If an attacker learns this key,
    # they can forge session cookies and impersonate any user.
    # In production, ALWAYS set this via an environment variable and never
    # commit a real key to source control.
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-me-before-deploying")

    # Path to the SQLite database file.
    DATABASE = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(__file__), "enrollment.db"))

    # --- Session cookie hardening ---
    SESSION_COOKIE_HTTPONLY = True     # JavaScript cannot read the cookie -> blocks session theft via XSS
    SESSION_COOKIE_SAMESITE = "Lax"    # Cookie not sent on most cross-site requests -> mitigates CSRF
    SESSION_COOKIE_SECURE = os.environ.get("FLASK_ENV") == "production"  # HTTPS-only cookie in production
    PERMANENT_SESSION_LIFETIME = 1800  # Session auto-expires after 30 minutes of inactivity

    # Caps request size (e.g. accidental huge form submissions / crude DoS attempts)
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024  # 1 MB
