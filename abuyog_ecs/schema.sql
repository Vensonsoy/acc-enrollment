-- schema.sql
-- ----------
-- Database schema for the Abuyog Community College Enrollment System.
-- Executed once at startup (see database.py -> init_db). Uses
-- "CREATE TABLE IF NOT EXISTS" so re-running it never destroys existing data.

-- USERS
-- One table for all three roles, distinguished by `role`. A CHECK constraint
-- stops any code path (even a future bug) from inserting an invalid role
-- directly at the database level - defense in depth, not just app-level validation.
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,                 -- NEVER store plaintext passwords
    full_name     TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('super_admin', 'admin', 'student')),
    is_active     INTEGER NOT NULL DEFAULT 1,    -- 0 disables login without deleting history
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- COURSES
-- created_by references the admin/super_admin who added the course, giving
-- an audit trail of who is responsible for each offering.
CREATE TABLE IF NOT EXISTS courses (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    course_code  TEXT NOT NULL UNIQUE,
    course_name  TEXT NOT NULL,
    description  TEXT,
    units        INTEGER NOT NULL DEFAULT 3,
    slots        INTEGER NOT NULL DEFAULT 40,    -- total seats offered
    created_by   INTEGER NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (created_by) REFERENCES users (id)
);

-- ENROLLMENTS
-- Join table between students and courses, carrying an approval workflow.
-- UNIQUE(student_id, course_id) stops duplicate enrollment rows at the DB
-- level even if the application logic has a race condition or a bug.
CREATE TABLE IF NOT EXISTS enrollments (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id   INTEGER NOT NULL,
    course_id    INTEGER NOT NULL,
    status       TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'dropped')) DEFAULT 'pending',
    enrolled_at  TEXT NOT NULL DEFAULT (datetime('now')),
    processed_by INTEGER,                         -- which admin approved/rejected this
    FOREIGN KEY (student_id) REFERENCES users (id),
    FOREIGN KEY (course_id) REFERENCES courses (id),
    FOREIGN KEY (processed_by) REFERENCES users (id),
    UNIQUE (student_id, course_id)
);
