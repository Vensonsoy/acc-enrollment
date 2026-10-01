"""
validators.py
-------------
Server-side input validation. Client-side (HTML `required`, `pattern`, etc.)
is convenient for UX but a browser can be bypassed entirely (curl, Postman,
a modified form) - so every rule that actually matters is re-checked here,
on the server, before anything touches the database.

Every function returns a plain string error message, or None if the input
is valid - callers collect these into a list and re-render the form with
the messages if the list isn't empty.
"""

import re

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{4,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_username(username):
    if not username or not USERNAME_RE.match(username):
        return "Username must be 4-20 characters: letters, numbers, or underscore only."
    return None


def validate_email(email):
    if not email or not EMAIL_RE.match(email):
        return "Please enter a valid email address."
    return None


def validate_password_strength(password):
    """
    Enforces a minimum bar so accounts aren't trivially guessable.
    Deliberately does NOT cap the maximum length or forbid special
    characters - both of those are outdated practices that push users
    toward weaker, more predictable passwords.
    """
    if not password or len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"[0-9]", password):
        return "Password must contain at least one letter and one number."
    return None


def validate_full_name(name):
    if not name or len(name.strip()) < 2:
        return "Please enter a full name."
    return None


def validate_course_code(code):
    if not code or not re.match(r"^[A-Za-z0-9\-]{2,15}$", code):
        return "Course code must be 2-15 characters (letters, numbers, hyphen)."
    return None


def validate_positive_int(value, field_name="Value"):
    try:
        n = int(value)
    except (TypeError, ValueError):
        return f"{field_name} must be a whole number."
    if n <= 0:
        return f"{field_name} must be greater than zero."
    return None
