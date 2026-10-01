"""
auth.py
-------
Cross-cutting security helpers used by every protected route in app.py:

  - login_required   : blocks anonymous access
  - role_required     : blocks access by users who ARE logged in but hold
                         the wrong role (this is authorization, not authentication)
  - generate_csrf_token / validate_csrf : Cross-Site Request Forgery protection
    for every state-changing (POST) form in the system

Keeping these in one module means every route enforces security the SAME
way - there's only one place to get it right (or, if a bug exists, only
one place to fix it).
"""

import secrets
from functools import wraps
from flask import session, redirect, url_for, flash, abort, request


def login_required(view):
    """
    Decorator: redirects anonymous visitors to /login instead of letting
    them reach a protected view. Also remembers where they were headed
    (`next`) so they land back on the right page after logging in.

    Usage:
        @app.route("/student/dashboard")
        @login_required
        def student_dashboard(): ...
    """
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped_view


def role_required(*allowed_roles):
    """
    Decorator FACTORY: returns a decorator that only lets through users
    whose session role is in `allowed_roles`.

        @role_required("admin", "super_admin")
        def manage_courses(): ...

    Must be stacked BELOW @login_required (closer to the function) so that
    session["role"] is guaranteed to already exist when this runs:

        @app.route(...)
        @login_required
        @role_required("admin")
        def view(): ...

    Returns HTTP 403 (Forbidden) rather than redirecting to login, because
    the problem here is "you're logged in but not allowed", which is a
    different situation from "you're not logged in at all".
    """
    def decorator(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            if session.get("role") not in allowed_roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped_view
    return decorator


def generate_csrf_token():
    """
    Returns the CSRF token for the current browser session, creating one
    (32 bytes of CSPRNG randomness, via `secrets`) the first time it's needed.

    Registered as a Jinja global in app.py so every template can do:
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    on every form that performs a state-changing action.
    """
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf(submitted_token):
    """
    Checks a token submitted with a POST request against the one stored
    in the user's session.

    Uses secrets.compare_digest instead of `==` for a CONSTANT-TIME
    comparison - a plain `==` on strings can leak timing information that
    lets an attacker guess the token byte-by-byte over many requests.

    Every POST route in app.py calls this first and aborts with 400 if it
    fails, which stops a malicious site from tricking a logged-in user's
    browser into submitting hidden forms to this app (CSRF).
    """
    session_token = session.get("csrf_token")
    if not session_token or not submitted_token:
        return False
    return secrets.compare_digest(session_token, submitted_token)
