"""Routes — VULNERABLE version.

Deliberate vulnerabilities in this file (to be fixed in Livrable 3):
- SQL queries built by string concatenation (SQLi)
- No CSRF tokens on POST forms
- No rate limiting / lockout on /login
- Error messages reveal whether an email exists
"""
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, abort, send_file
import bcrypt
from .db import get_db

bp = Blueprint("main", __name__)


# ---------- Helpers ----------

def current_user():
    """Return the row of the logged-in user, or None."""
    uid = session.get("user_id")
    if not uid:
        return None
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    conn.close()
    return row


def login_required(view):
    from functools import wraps
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("main.login"))
        return view(*args, **kwargs)
    return wrapped


# ---------- Public ----------

@bp.route("/")
def index():
    if current_user():
        return redirect(url_for("main.dashboard"))
    return redirect(url_for("main.login"))


# ---------- Auth ----------

@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Email et mot de passe requis.")
            return render_template("register.html")

        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        # VULN: SQL by string concatenation (SQLi)
        conn = get_db()
        try:
            query = f"INSERT INTO users (email, password_hash) VALUES ('{email}', '{pw_hash}')"
            conn.executescript(query)
            conn.commit()
        except Exception as e:
            flash(f"Erreur : {e}")
            conn.close()
            return render_template("register.html")
        conn.close()

        # TODO (Ines): after INSERT, generate ECDSA keypair + CSR + sign with CA,
        # then UPDATE users SET public_key_pem=?, private_key_pem=?, certificate_pem=? WHERE email=?

        flash("Compte créé, vous pouvez vous connecter.")
        return redirect(url_for("main.login"))

    return render_template("register.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        # VULN: SQL by string concatenation (SQLi via email)
        conn = get_db()
        query = f"SELECT * FROM users WHERE email = '{email}'"
        user = conn.execute(query).fetchone()
        conn.close()

        # VULN: no rate limiting, no lockout, detailed error message
        if user is None:
            flash("Aucun compte avec cet email.")
            return render_template("login.html")
        if not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
            flash("Mot de passe incorrect.")
            return render_template("login.html")

        session["user_id"] = user["id"]
        session["user_email"] = user["email"]
        return redirect(url_for("main.dashboard"))

    return render_template("login.html")


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("main.login"))


# ---------- Dashboard ----------

@bp.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    conn = get_db()
    # Files I own
    owned = conn.execute(
        "SELECT * FROM files WHERE owner_id = ? ORDER BY created_at DESC",
        (user["id"],)
    ).fetchall()
    # Files shared with me
    shared = conn.execute("""
        SELECT f.*, u.email AS owner_email
        FROM files f
        JOIN shares s ON s.file_id = f.id
        JOIN users u ON u.id = f.owner_id
        WHERE s.recipient_id = ?
        ORDER BY s.granted_at DESC
    """, (user["id"],)).fetchall()
    conn.close()
    return render_template("dashboard.html", user=user, owned=owned, shared=shared)


# ---------- Files (skeletons for Thursday) ----------

@bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    # TODO (Thursday): handle file upload + call crypto helpers
    if request.method == "POST":
        flash("Upload pas encore implémenté — à faire jeudi.")
        return redirect(url_for("main.dashboard"))
    return render_template("upload.html")


@bp.route("/download/<int:file_id>")
@login_required
def download(file_id):
    # VULN (IDOR): no ownership/share check — any logged-in user can download any file
    # TODO (Thursday): fetch file, decrypt AES-GCM, verify SHA-256, verify ECDSA signature
    flash("Download pas encore implémenté — à faire jeudi.")
    return redirect(url_for("main.dashboard"))


@bp.route("/share/<int:file_id>", methods=["GET", "POST"])
@login_required
def share(file_id):
    # VULN: no CSRF token on this POST
    if request.method == "POST":
        recipient_email = request.form.get("recipient_email", "").strip()
        conn = get_db()
        recipient = conn.execute(
            "SELECT id FROM users WHERE email = ?", (recipient_email,)
        ).fetchone()
        if not recipient:
            conn.close()
            flash("Destinataire introuvable.")
            return redirect(url_for("main.dashboard"))
        conn.execute(
            "INSERT INTO shares (file_id, recipient_id) VALUES (?, ?)",
            (file_id, recipient["id"])
        )
        conn.commit()
        conn.close()
        flash("Partagé.")
        return redirect(url_for("main.dashboard"))
    return render_template("share.html", file_id=file_id)
