"""Flask application factory."""
from flask import Flask


def create_app():
    app = Flask(__name__)
    # VULN: weak secret key, hardcoded in source (Livrable 3: move to env + rotate)
    app.secret_key = "dev-secret-change-me"

    # VULN: default Flask session cookie has no HttpOnly/Secure/SameSite hardening
    # (Livrable 3: set SESSION_COOKIE_HTTPONLY, SECURE, SAMESITE)

    from . import routes
    app.register_blueprint(routes.bp)

    return app
