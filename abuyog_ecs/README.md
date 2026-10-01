# Abuyog Community College - Enrollment System

Flask + SQLite enrollment system with three roles: **Super Admin**, **Admin**, **Student**.

## Setup

```bash
cd abuyog_ecs
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Create the database + a default Super Admin account (run once)
flask --app app init-db

# Start the dev server
flask --app app run --debug
```

Open http://127.0.0.1:5000

The `init-db` command prints a default Super Admin username/password to
the console. **Log in and change that password immediately** (this demo
doesn't ship a "change password" screen — add one before real use, see
"Suggested Next Steps" below).

## Roles

| Role | How the account is created | Can do |
|---|---|---|
| Super Admin | Seeded once by `flask init-db` | Create/disable Admin accounts, view system-wide stats |
| Admin | Created only by a Super Admin | Create/delete courses, approve/reject enrollments, view student roster |
| Student | Self-registers at `/register` | Browse courses, request enrollment, drop courses |

## Project Structure

```
abuyog_ecs/
├── app.py            # All routes (auth, super_admin, admin, student)
├── auth.py           # login_required / role_required decorators, CSRF helpers
├── config.py         # Secret key, DB path, cookie security flags
├── database.py       # SQLite connection handling, schema init, seeding
├── validators.py      # Server-side input validation
├── schema.sql         # Table definitions
├── requirements.txt
├── templates/         # Jinja2 templates, split by role
└── static/css/
```

## Security Measures (see inline code comments for the "why" of each)

1. **SQL Injection** — every query uses `?` parameterized placeholders via
   `sqlite3`. No query anywhere is built with string concatenation/f-strings.
2. **Password storage** — passwords are hashed with
   `werkzeug.security.generate_password_hash` (PBKDF2 + per-password salt)
   and verified with `check_password_hash`. Plaintext passwords are never
   stored or logged.
3. **Session security** — `HttpOnly`, `SameSite=Lax` cookies, a 30-minute
   idle timeout, and `session.clear()` on every login (defends against
   session fixation).
4. **CSRF protection** — every state-changing form includes a per-session
   token (`auth.py: generate_csrf_token`); every POST route validates it
   with a constant-time comparison before doing anything else.
5. **Role-based access control (RBAC)** — `@login_required` and
   `@role_required(...)` decorators gate every route; a role is only ever
   read from the database/session, never trusted from form input.
6. **Insecure Direct Object Reference (IDOR) prevention** — student
   actions like `drop` filter by `student_id = session['user_id']` AND
   the record id, so a student can't act on another student's records
   just by editing a URL/id.
7. **XSS mitigation** — Jinja2 autoescapes all template output by default;
   no template uses the `|safe` filter on user-supplied data.
8. **Input validation** — `validators.py` re-checks everything server-side
   (usernames, emails, password strength, numeric fields) regardless of
   what the browser's HTML5 validation already did, since client-side
   checks can always be bypassed.
9. **Database-level constraints** — `UNIQUE`, `CHECK`, and `FOREIGN KEY`
   constraints in `schema.sql` back up the application logic so a bug or
   race condition can't silently create invalid rows (duplicate
   enrollments, bad roles, orphaned foreign keys).
10. **No privilege escalation path** — the public `/register` route can
    only ever create `student` accounts; Admin accounts can only be
    created by an authenticated Super Admin through a route gated with
    `@role_required("super_admin")`.
11. **Generic auth error messages** — the login form gives the same error
    for "wrong password" and "user doesn't exist," preventing username
    enumeration.
12. **No stack traces leaked** — custom error handlers for 400/403/404
    replace Flask's default HTML error pages so internals are never
    exposed to end users. `debug=True` is explicitly flagged as
    development-only in `app.py`.

## Suggested Next Steps for Production

- Add a "change password" / "forgot password" flow.
- Move `SECRET_KEY` and any admin bootstrap credentials to real
  environment variables / a secrets manager — never hard-code them.
- Put the app behind HTTPS and set `SESSION_COOKIE_SECURE=True`
  (already wired to `FLASK_ENV=production` in `config.py`).
- Add rate limiting on `/login` (e.g. Flask-Limiter) to slow down
  brute-force attempts.
- Consider migrating to PostgreSQL/MySQL if concurrent write load grows
  beyond what SQLite comfortably handles.
- Add server-side logging/auditing of admin actions (who approved what,
  when).
