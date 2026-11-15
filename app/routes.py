"""Routes — VERSION VULNERABLE (Livrable 2).

Failles volontaires dans ce fichier (corrigées dans la branche `secure`) :
- V1/V2  requêtes SQL par concaténation (register, login)
- V3     aucun jeton CSRF sur les formulaires POST
- V6/V7  pas de limitation des tentatives, messages d'erreur détaillés
- V8     IDOR : /download, /verify et /share ne vérifient pas les droits
- V9     clé AES de chaque fichier stockée en clair en base
- V10    clé privée ECDSA de l'utilisateur stockée en clair en base
- V11    aucune validation du type, de la taille ou du nom du fichier déposé
Voir docs/vulnerabilities_known.md
"""
import datetime as dt
import io
import os
from functools import wraps

import bcrypt
from cryptography.hazmat.primitives import serialization
from flask import (Blueprint, flash, redirect, render_template, request,
                   send_file, session, url_for)

from security import certificates as pki
from security import crypto, hashing, signature

from .db import get_db

bp = Blueprint("main", __name__)

STORAGE_DIR = "storage"
CA_DIR = os.path.join("pki", "ca")
AUDIT_LOG = "audit.log"


# ---------- Helpers ----------

def audit(action, result, target=""):
    """Journal d'audit horodaté (sans donnée sensible)."""
    line = "{} | user={} | {} | target={} | {}\n".format(
        dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        session.get("user_email", "-"), action, target, result)
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(line)


def get_ca():
    """Charge l'AC locale ; la crée au premier lancement."""
    passphrase = os.environ.get("CA_PASSPHRASE")
    passphrase = passphrase.encode() if passphrase else None
    if not os.path.exists(os.path.join(CA_DIR, "ca.cert.pem")):
        return pki.create_ca(ca_dir=CA_DIR, passphrase=passphrase)
    return pki.load_ca(CA_DIR, passphrase=passphrase)


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    conn.close()
    return row


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("main.login"))
        return view(*args, **kwargs)
    return wrapped


def open_and_verify(file_row):
    """Flux B : certificat -> déchiffrement GCM -> SHA-256 -> signature ECDSA.

    Retourne (clair ou None, liste de contrôles, infos du certificat ou None).
    Chaque contrôle est un dict {label, ok, detail}.
    """
    checks = []
    conn = get_db()
    owner = conn.execute("SELECT * FROM users WHERE id = ?",
                         (file_row["owner_id"],)).fetchone()
    conn.close()

    # 1. Certificat du propriétaire : chaîne, dates, usage, identité
    cert, cert_info = None, None
    try:
        _, ca_cert = get_ca()
        cert = pki.verify_certificate(owner["certificate_pem"].encode(), ca_cert,
                                      expected_email=owner["email"])
        cert_info = pki.certificate_info(cert)
        checks.append({"label": "Certificat du propriétaire", "ok": True,
                       "detail": "Émis par l'AC locale, valide, identité conforme"})
    except Exception as exc:  # certificat absent, expiré, forgé...
        checks.append({"label": "Certificat du propriétaire", "ok": False,
                       "detail": str(exc)})

    # 2. Déchiffrement AES-256-GCM (le tag détecte toute altération du chiffré)
    plaintext = None
    try:
        plaintext = crypto.decrypt_file_from_disk(
            file_row["aes_key"], file_row["nonce"], STORAGE_DIR,
            file_row["stored_name"])
        checks.append({"label": "Déchiffrement AES-256-GCM", "ok": True,
                       "detail": "Tag d'authentification valide"})
    except Exception as exc:
        checks.append({"label": "Déchiffrement AES-256-GCM", "ok": False,
                       "detail": str(exc)})

    # 3. Empreinte SHA-256 du clair comparée à la référence en base
    if plaintext is not None:
        ok = hashing.verify_hash(plaintext, file_row["sha256_hash"])
        checks.append({"label": "Intégrité SHA-256", "ok": ok,
                       "detail": "Intégrité vérifiée" if ok
                       else "Échec de vérification : empreinte différente"})
    else:
        checks.append({"label": "Intégrité SHA-256", "ok": False,
                       "detail": "Non vérifiable (déchiffrement impossible)"})

    # 4. Signature ECDSA vérifiée avec la clé publique du certificat
    if cert is not None:
        ok = signature.verify_signature(pki.certificate_public_key(cert),
                                        file_row["signature"],
                                        file_row["sha256_hash"])
        checks.append({"label": "Signature ECDSA P-256", "ok": ok,
                       "detail": "Signature valide (" + owner["email"] + ")" if ok
                       else "Signature invalide"})
    else:
        checks.append({"label": "Signature ECDSA P-256", "ok": False,
                       "detail": "Non vérifiable (certificat refusé)"})

    return plaintext, checks, cert_info


def get_file(file_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    conn.close()
    return row


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

        # VULN V1 : SQL par concaténation
        conn = get_db()
        try:
            query = f"INSERT INTO users (email, password_hash) VALUES ('{email}', '{pw_hash}')"
            conn.executescript(query)
            conn.commit()
        except Exception as e:
            flash(f"Erreur : {e}")
            conn.close()
            return render_template("register.html")

        # Paire de clés ECDSA P-256 + certificat X.509 signé par l'AC locale
        try:
            ca_key, ca_cert = get_ca()
            private_key = signature.generate_keypair()
            cert_pem = pki.issue_user_certificate(
                private_key.public_key(), email, ca_key, ca_cert)
            # VULN V10 : clé privée stockée en clair (non chiffrée)
            private_pem = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption())
            conn.execute(
                "UPDATE users SET public_key_pem = ?, private_key_pem = ?, "
                "certificate_pem = ? WHERE email = ?",
                (signature.public_key_pem(private_key).decode(),
                 private_pem.decode(), cert_pem.decode(), email))
            conn.commit()
        except Exception as e:
            flash(f"Compte créé mais certificat non émis : {e}")
        conn.close()

        audit("register", "success", email)
        flash("Compte créé, vous pouvez vous connecter.")
        return redirect(url_for("main.login"))

    return render_template("register.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        # VULN V2 : SQL par concaténation
        conn = get_db()
        query = f"SELECT * FROM users WHERE email = '{email}'"
        try:
            user = conn.execute(query).fetchone()
        except Exception as e:
            conn.close()
            flash(f"Erreur SQL : {e}")
            return render_template("login.html")
        conn.close()

        # VULN V6/V7 : pas de limitation, messages qui révèlent l'existence du compte
        if user is None:
            audit("login", "fail", email)
            flash("Aucun compte avec cet email.")
            return render_template("login.html")
        if not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
            audit("login", "fail", email)
            flash("Mot de passe incorrect.")
            return render_template("login.html")

        session["user_id"] = user["id"]
        session["user_email"] = user["email"]
        audit("login", "success", email)
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
    owned = conn.execute(
        "SELECT * FROM files WHERE owner_id = ? ORDER BY created_at DESC",
        (user["id"],)).fetchall()
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


# ---------- Fichiers ----------

@bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    """Flux A : chiffrement AES-GCM, empreinte SHA-256, signature ECDSA."""
    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename:
            flash("Aucun fichier sélectionné.")
            return render_template("upload.html")

        user = current_user()
        if not user["private_key_pem"]:
            flash("Ce compte n'a pas de clé de signature : recréez le compte.")
            return redirect(url_for("main.dashboard"))

        # VULN V11 : aucun contrôle de type, de taille ni de nom
        data = f.read()

        file_key = crypto.generate_file_key()
        stored_name, nonce = crypto.encrypt_file_to_disk(file_key, data, STORAGE_DIR)
        digest = hashing.sha256_bytes(data)
        private_key = serialization.load_pem_private_key(
            user["private_key_pem"].encode(), password=None)
        sig = signature.sign_hash(private_key, digest)

        conn = get_db()
        # VULN V9 : clé AES stockée en clair à côté des métadonnées
        conn.execute(
            "INSERT INTO files (owner_id, original_name, stored_name, nonce, "
            "aes_key, sha256_hash, signature) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user["id"], f.filename, stored_name, nonce, file_key, digest, sig))
        conn.commit()
        conn.close()

        audit("upload", "success", stored_name)
        flash("Fichier chiffré, signé et déposé.")
        return redirect(url_for("main.dashboard"))
    return render_template("upload.html")


@bp.route("/verify/<int:file_id>")
@login_required
def verify(file_id):
    # VULN V8 (IDOR) : aucun contrôle propriétaire / destinataire
    file_row = get_file(file_id)
    if file_row is None:
        flash("Fichier introuvable.")
        return redirect(url_for("main.dashboard"))
    _, checks, cert_info = open_and_verify(file_row)
    ok = all(c["ok"] for c in checks)
    audit("verify", "success" if ok else "FAIL", file_row["stored_name"])
    return render_template("verify.html", file=file_row, checks=checks,
                           cert_info=cert_info, all_ok=ok)


@bp.route("/download/<int:file_id>")
@login_required
def download(file_id):
    # VULN V8 (IDOR) : aucun contrôle propriétaire / destinataire
    file_row = get_file(file_id)
    if file_row is None:
        flash("Fichier introuvable.")
        return redirect(url_for("main.dashboard"))

    plaintext, checks, cert_info = open_and_verify(file_row)
    if plaintext is None or not all(c["ok"] for c in checks):
        audit("download", "FAIL verification", file_row["stored_name"])
        return render_template("verify.html", file=file_row, checks=checks,
                               cert_info=cert_info, all_ok=False)

    audit("download", "success, verified", file_row["stored_name"])
    return send_file(io.BytesIO(plaintext), as_attachment=True,
                     download_name=file_row["original_name"])


@bp.route("/share/<int:file_id>", methods=["GET", "POST"])
@login_required
def share(file_id):
    # VULN V3 : pas de jeton CSRF ; VULN V8 : pas de contrôle de propriété
    if request.method == "POST":
        recipient_email = request.form.get("recipient_email", "").strip()
        conn = get_db()
        recipient = conn.execute(
            "SELECT id FROM users WHERE email = ?", (recipient_email,)).fetchone()
        if not recipient:
            conn.close()
            flash("Destinataire introuvable.")
            return redirect(url_for("main.dashboard"))
        conn.execute("INSERT INTO shares (file_id, recipient_id) VALUES (?, ?)",
                     (file_id, recipient["id"]))
        conn.commit()
        conn.close()
        audit("share", "success", recipient_email)
        flash("Partagé.")
        return redirect(url_for("main.dashboard"))
    return render_template("share.html", file_id=file_id)
