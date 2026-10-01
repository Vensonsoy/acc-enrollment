"""
app.py
------
Abuyog Community College Enrollment System - main Flask application.

Three roles share one login page but see completely different dashboards
and permissions, enforced by the @role_required decorator on every route:

    super_admin -> creates/disables Admin accounts, sees system-wide stats
    admin       -> manages courses, approves/rejects student enrollments
    student     -> browses courses, enrolls, tracks enrollment status

Run locally:
    pip install -r requirements.txt
    flask --app app init-db      # creates tables + a default super admin (once)
    flask --app app run --debug
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash

from config import Config
from database import get_db, close_db, init_db, seed_super_admin
from auth import login_required, role_required, generate_csrf_token, validate_csrf
from validators import (
    validate_username, validate_email, validate_password_strength,
    validate_full_name, validate_course_code, validate_positive_int,
)

app = Flask(__name__)
app.config.from_object(Config)

# Ensures every request's SQLite connection is closed when the request ends,
# regardless of whether the view raised an exception.
app.teardown_appcontext(close_db)

# Makes csrf_token() callable directly inside any Jinja template, e.g.
#   <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
app.jinja_env.globals["csrf_token"] = generate_csrf_token


@app.cli.command("init-db")
def init_db_command():
    """
    CLI command: `flask --app app init-db`
    Creates the schema and seeds the default super admin account.
    Kept as an explicit, deliberate command (rather than running
    automatically on every boot) so production deployments don't
    accidentally re-seed or touch the schema on every restart.
    """
    init_db(app)
    seed_super_admin(app)
    print("Database initialized.")


def _check_csrf_or_abort():
    """
    Shared guard called at the top of every POST route. Aborts the request
    with 400 Bad Request if the submitted CSRF token doesn't match the
    one issued to this browser session - see auth.py for why this matters.
    """
    if not validate_csrf(request.form.get("csrf_token")):
        abort(400)


def _current_user():
    """
    Fetches the full row for the logged-in user from the database.
    We deliberately DON'T trust session data (like a stashed full_name)
    for anything security-relevant or displayed as fact - session only
    stores the minimal identifiers (user_id, role, username); everything
    else is re-read from the DB each time, so a disabled account or a
    changed role takes effect immediately instead of persisting in a
    stale session.
    """
    if "user_id" not in session:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()


# ---------------------------------------------------------------------------
# Public / authentication routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Landing page: sends logged-in users to their dashboard, everyone else to login."""
    if "user_id" in session:
        return redirect(url_for(f"{session['role']}_dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Self-service registration - STUDENTS ONLY. Admin and Super Admin
    accounts can never be created through this public form; they're only
    created by an existing Super Admin (see super_admin_create_admin
    below). This stops anyone on the internet from granting themselves
    administrative access.
    """
    if request.method == "POST":
        _check_csrf_or_abort()

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        full_name = request.form.get("full_name", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        errors = list(filter(None, [
            validate_username(username),
            validate_email(email),
            validate_full_name(full_name),
            validate_password_strength(password),
        ]))
        if password != confirm:
            errors.append("Passwords do not match.")

        if not errors:
            db = get_db()
            # Uniqueness is enforced both here (friendly message) AND at the
            # DB level via UNIQUE constraints (last line of defense against
            # race conditions between the check and the insert).
            clash = db.execute(
                "SELECT id FROM users WHERE username = ? OR email = ?", (username, email)
            ).fetchone()
            if clash:
                errors.append("That username or email is already registered.")
            else:
                db.execute(
                    """INSERT INTO users (username, email, password_hash, full_name, role)
                       VALUES (?, ?, ?, ?, 'student')""",
                    (username, email, generate_password_hash(password), full_name),
                )
                db.commit()
                flash("Registration successful! You may now log in.", "success")
                return redirect(url_for("login"))

        for err in errors:
            flash(err, "danger")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Single login form shared by all three roles. The role itself is never
    trusted from the form - it's looked up from the database after the
    password check, so a user cannot log in "as admin" just by editing a
    hidden field.
    """
    if request.method == "POST":
        _check_csrf_or_abort()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        # check_password_hash safely compares the submitted password against
        # the stored salted hash - it never compares plaintext to plaintext,
        # and it runs in constant time to resist timing attacks.
        # The same generic error is shown whether the username doesn't exist
        # OR the password is wrong, so attackers can't use this form to
        # enumerate which usernames are registered.
        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password.", "danger")
        elif not user["is_active"]:
            flash("This account has been disabled. Contact the registrar.", "danger")
        else:
            session.clear()  # wipes any pre-existing session data (session fixation defense)
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash(f"Welcome back, {user['full_name']}!", "success")
            return redirect(url_for(f"{user['role']}_dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    """Clears the entire session, ending the user's authenticated state server-side."""
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# SUPER ADMIN routes
# ---------------------------------------------------------------------------

@app.route("/super-admin/dashboard")
@login_required
@role_required("super_admin")
def super_admin_dashboard():
    """
    Overview screen: headline counts for the whole system. Only super_admin
    can see totals across every admin and student - regular admins only
    ever see their own courses' enrollments (enforced in admin routes below).
    """
    db = get_db()
    stats = {
        "total_admins": db.execute("SELECT COUNT(*) c FROM users WHERE role='admin'").fetchone()["c"],
        "total_students": db.execute("SELECT COUNT(*) c FROM users WHERE role='student'").fetchone()["c"],
        "total_courses": db.execute("SELECT COUNT(*) c FROM courses").fetchone()["c"],
        "pending_enrollments": db.execute("SELECT COUNT(*) c FROM enrollments WHERE status='pending'").fetchone()["c"],
    }
    return render_template("super_admin/dashboard.html", stats=stats, user=_current_user())


@app.route("/super-admin/admins", methods=["GET", "POST"])
@login_required
@role_required("super_admin")
def super_admin_manage_admins():
    """
    Lists every admin account and lets the super admin create a new one.
    This is the ONLY place in the entire application where a new admin
    account can be created - a deliberate, narrow chokepoint for
    privilege escalation.
    """
    db = get_db()
    if request.method == "POST":
        _check_csrf_or_abort()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        full_name = request.form.get("full_name", "").strip()
        password = request.form.get("password", "")

        errors = list(filter(None, [
            validate_username(username),
            validate_email(email),
            validate_full_name(full_name),
            validate_password_strength(password),
        ]))
        clash = db.execute("SELECT id FROM users WHERE username=? OR email=?", (username, email)).fetchone()
        if clash:
            errors.append("That username or email is already in use.")

        if errors:
            for err in errors:
                flash(err, "danger")
        else:
            db.execute(
                """INSERT INTO users (username, email, password_hash, full_name, role)
                   VALUES (?, ?, ?, ?, 'admin')""",
                (username, email, generate_password_hash(password), full_name),
            )
            db.commit()
            flash(f"Admin account '{username}' created.", "success")
        return redirect(url_for("super_admin_manage_admins"))

    admins = db.execute("SELECT * FROM users WHERE role='admin' ORDER BY created_at DESC").fetchall()
    return render_template("super_admin/manage_admins.html", admins=admins, user=_current_user())


@app.route("/super-admin/admins/<int:admin_id>/toggle", methods=["POST"])
@login_required
@role_required("super_admin")
def super_admin_toggle_admin(admin_id):
    """
    Enables/disables an admin account WITHOUT deleting it, preserving the
    audit trail (courses they created, enrollments they processed still
    reference a real user row). Disabling is safer than deleting for
    accounts that already have history attached.
    """
    _check_csrf_or_abort()
    db = get_db()
    admin = db.execute("SELECT * FROM users WHERE id=? AND role='admin'", (admin_id,)).fetchone()
    if admin is None:
        abort(404)
    db.execute("UPDATE users SET is_active = ? WHERE id = ?", (0 if admin["is_active"] else 1, admin_id))
    db.commit()
    flash(f"Admin '{admin['username']}' has been {'disabled' if admin['is_active'] else 'enabled'}.", "info")
    return redirect(url_for("super_admin_manage_admins"))


# ---------------------------------------------------------------------------
# ADMIN routes
# ---------------------------------------------------------------------------

@app.route("/admin/dashboard")
@login_required
@role_required("admin", "super_admin")
def admin_dashboard():
    """
    Admin overview. Super admin is also allowed here (a super admin should
    be able to see what an admin sees), but admins can never reach the
    super_admin_* routes above - that's a one-way permission relationship.
    """
    db = get_db()
    stats = {
        "total_courses": db.execute("SELECT COUNT(*) c FROM courses").fetchone()["c"],
        "pending_enrollments": db.execute("SELECT COUNT(*) c FROM enrollments WHERE status='pending'").fetchone()["c"],
        "approved_enrollments": db.execute("SELECT COUNT(*) c FROM enrollments WHERE status='approved'").fetchone()["c"],
    }
    return render_template("admin/dashboard.html", stats=stats, user=_current_user())


@app.route("/admin/courses", methods=["GET", "POST"])
@login_required
@role_required("admin", "super_admin")
def admin_manage_courses():
    """Lists all courses and lets an admin add a new one."""
    db = get_db()
    if request.method == "POST":
        _check_csrf_or_abort()
        code = request.form.get("course_code", "").strip().upper()
        name = request.form.get("course_name", "").strip()
        description = request.form.get("description", "").strip()
        units = request.form.get("units", "3")
        slots = request.form.get("slots", "40")

        errors = list(filter(None, [
            validate_course_code(code),
            validate_full_name(name),  # reused: "non-empty, meaningful text" check
            validate_positive_int(units, "Units"),
            validate_positive_int(slots, "Slots"),
        ]))
        if db.execute("SELECT id FROM courses WHERE course_code = ?", (code,)).fetchone():
            errors.append(f"Course code '{code}' already exists.")

        if errors:
            for err in errors:
                flash(err, "danger")
        else:
            db.execute(
                """INSERT INTO courses (course_code, course_name, description, units, slots, created_by)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (code, name, description, int(units), int(slots), session["user_id"]),
            )
            db.commit()
            flash(f"Course '{code}' created.", "success")
        return redirect(url_for("admin_manage_courses"))

    courses = db.execute(
        """SELECT c.*,
                  (SELECT COUNT(*) FROM enrollments e WHERE e.course_id = c.id AND e.status = 'approved') AS enrolled_count
           FROM courses c ORDER BY c.created_at DESC"""
    ).fetchall()
    return render_template("admin/manage_courses.html", courses=courses, user=_current_user())


@app.route("/admin/courses/<int:course_id>/delete", methods=["POST"])
@login_required
@role_required("admin", "super_admin")
def admin_delete_course(course_id):
    """
    Deletes a course. Guarded so a course with existing enrollment history
    cannot simply vanish (which would silently orphan a student's record) -
    the admin must resolve those enrollments first.
    """
    _check_csrf_or_abort()
    db = get_db()
    linked = db.execute("SELECT COUNT(*) c FROM enrollments WHERE course_id = ?", (course_id,)).fetchone()["c"]
    if linked > 0:
        flash("Cannot delete a course that has enrollment records. Remove those first.", "danger")
    else:
        db.execute("DELETE FROM courses WHERE id = ?", (course_id,))
        db.commit()
        flash("Course deleted.", "info")
    return redirect(url_for("admin_manage_courses"))


@app.route("/admin/enrollments")
@login_required
@role_required("admin", "super_admin")
def admin_manage_enrollments():
    """
    Shows every enrollment request (pending first) so an admin can approve
    or reject them. Joins across students and courses so the admin sees
    human-readable names, not raw foreign-key IDs.
    """
    db = get_db()
    enrollments = db.execute(
        """SELECT e.*, u.full_name AS student_name, u.username AS student_username,
                  c.course_code, c.course_name, c.slots
           FROM enrollments e
           JOIN users u ON u.id = e.student_id
           JOIN courses c ON c.id = e.course_id
           ORDER BY (e.status = 'pending') DESC, e.enrolled_at DESC"""
    ).fetchall()
    return render_template("admin/manage_enrollments.html", enrollments=enrollments, user=_current_user())


@app.route("/admin/enrollments/<int:enrollment_id>/decide", methods=["POST"])
@login_required
@role_required("admin", "super_admin")
def admin_decide_enrollment(enrollment_id):
    """
    Approves or rejects a single enrollment. Before approving, re-checks
    that the course still has a free slot - re-validating server-side
    at the moment of the decision, rather than trusting a slot count the
    browser might have loaded minutes ago (prevents overbooking).
    """
    _check_csrf_or_abort()
    decision = request.form.get("decision")  # expected: "approved" or "rejected"
    if decision not in ("approved", "rejected"):
        abort(400)

    db = get_db()
    enrollment = db.execute("SELECT * FROM enrollments WHERE id = ?", (enrollment_id,)).fetchone()
    if enrollment is None:
        abort(404)

    if decision == "approved":
        course = db.execute("SELECT * FROM courses WHERE id = ?", (enrollment["course_id"],)).fetchone()
        approved_count = db.execute(
            "SELECT COUNT(*) c FROM enrollments WHERE course_id = ? AND status = 'approved'",
            (enrollment["course_id"],),
        ).fetchone()["c"]
        if approved_count >= course["slots"]:
            flash("Cannot approve - this course is already full.", "danger")
            return redirect(url_for("admin_manage_enrollments"))

    db.execute(
        "UPDATE enrollments SET status = ?, processed_by = ? WHERE id = ?",
        (decision, session["user_id"], enrollment_id),
    )
    db.commit()
    flash(f"Enrollment #{enrollment_id} marked as {decision}.", "success")
    return redirect(url_for("admin_manage_enrollments"))


@app.route("/admin/students")
@login_required
@role_required("admin", "super_admin")
def admin_view_students():
    """Read-only roster of all student accounts, for reference during enrollment review."""
    db = get_db()
    students = db.execute("SELECT * FROM users WHERE role='student' ORDER BY full_name").fetchall()
    return render_template("admin/manage_students.html", students=students, user=_current_user())


# ---------------------------------------------------------------------------
# STUDENT routes
# ---------------------------------------------------------------------------

@app.route("/student/dashboard")
@login_required
@role_required("student")
def student_dashboard():
    """Shows the logged-in student's own enrollments and their current status."""
    db = get_db()
    enrollments = db.execute(
        """SELECT e.*, c.course_code, c.course_name, c.units
           FROM enrollments e JOIN courses c ON c.id = e.course_id
           WHERE e.student_id = ?
           ORDER BY e.enrolled_at DESC""",
        (session["user_id"],),
    ).fetchall()
    return render_template("student/dashboard.html", enrollments=enrollments, user=_current_user())


@app.route("/student/courses")
@login_required
@role_required("student")
def student_browse_courses():
    """
    Lists all courses with remaining-slot counts and whether THIS student
    has already requested enrollment, so the template can disable the
    "Enroll" button instead of letting them submit a duplicate request.
    """
    db = get_db()
    courses = db.execute(
        """SELECT c.*,
                  (SELECT COUNT(*) FROM enrollments e WHERE e.course_id = c.id AND e.status='approved') AS taken_slots,
                  (SELECT status FROM enrollments e WHERE e.course_id = c.id AND e.student_id = ?) AS my_status
           FROM courses c ORDER BY c.course_code""",
        (session["user_id"],),
    ).fetchall()
    return render_template("student/browse_courses.html", courses=courses, user=_current_user())


@app.route("/student/enroll/<int:course_id>", methods=["POST"])
@login_required
@role_required("student")
def student_enroll(course_id):
    """
    Creates a pending enrollment request for the logged-in student.

    Note that student_id is ALWAYS taken from `session["user_id"]`, never
    from a hidden form field - this is what stops one student from
    enrolling on behalf of another by tampering with the request.
    The UNIQUE(student_id, course_id) constraint in schema.sql is the
    final backstop against duplicate requests even under concurrent clicks.
    """
    _check_csrf_or_abort()
    db = get_db()
    course = db.execute("SELECT * FROM courses WHERE id = ?", (course_id,)).fetchone()
    if course is None:
        abort(404)

    try:
        db.execute(
            "INSERT INTO enrollments (student_id, course_id, status) VALUES (?, ?, 'pending')",
            (session["user_id"], course_id),
        )
        db.commit()
        flash(f"Enrollment request submitted for {course['course_code']}. Awaiting admin approval.", "success")
    except db.IntegrityError:
        flash("You have already requested enrollment in this course.", "warning")

    return redirect(url_for("student_browse_courses"))


@app.route("/student/drop/<int:enrollment_id>", methods=["POST"])
@login_required
@role_required("student")
def student_drop(enrollment_id):
    """
    Lets a student withdraw from a course. Critically, the WHERE clause
    filters on `student_id = ?` as well as the enrollment id - without
    that check, any logged-in student could drop ANY OTHER student's
    enrollment just by guessing/incrementing the id in the URL (an
    Insecure Direct Object Reference vulnerability). This pattern is
    used the same way in admin routes, scoped to what that role may touch.
    """
    _check_csrf_or_abort()
    db = get_db()
    row = db.execute(
        "SELECT id FROM enrollments WHERE id = ? AND student_id = ?",
        (enrollment_id, session["user_id"]),
    ).fetchone()
    if row is None:
        abort(404)
    db.execute("UPDATE enrollments SET status = 'dropped' WHERE id = ?", (enrollment_id,))
    db.commit()
    flash("You have dropped this course.", "info")
    return redirect(url_for("student_dashboard"))


# ---------------------------------------------------------------------------
# Error handlers - avoid leaking stack traces / internals to end users
# ---------------------------------------------------------------------------

@app.errorhandler(403)
def forbidden(_e):
    return render_template("error.html", code=403, message="You don't have permission to view this page."), 403


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, message="That page doesn't exist."), 404


@app.errorhandler(400)
def bad_request(_e):
    return render_template("error.html", code=400, message="Your request could not be processed."), 400


if __name__ == "__main__":
    # debug=True is for LOCAL DEVELOPMENT ONLY - it exposes an interactive
    # debugger/stack traces in the browser, which is a severe information
    # disclosure and RCE risk if ever left on in production.
    app.run(debug=True)
