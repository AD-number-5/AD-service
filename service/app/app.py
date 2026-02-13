import socket
from datetime import timedelta
import secrets
from flask import Flask, redirect, url_for
from flask_jwt_extended import JWTManager, unset_jwt_cookies
from models import db
from routes import routes_bp

NAME_LEN = 1000
IN_CHUNK = 42000
MAX_OUT = 42000

def create_app():
    app = Flask(__name__)

    app.config["SECRET_KEY"] = secrets.token_hex(32)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite3"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["JWT_SECRET_KEY"] = secrets.token_hex(32)
    app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
    app.config["JWT_ACCESS_COOKIE_NAME"] = "access_token"
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=12)
    app.config["JWT_COOKIE_CSRF_PROTECT"] = False

    db.init_app(app)
    jwt = JWTManager(app)

    @jwt.unauthorized_loader
    def unauthorized_callback(callback):
        return "Forbidden", 403

    @jwt.invalid_token_loader
    def invalid_token_callback(callback):
        resp = redirect(url_for("routes.login"))
        unset_jwt_cookies(resp)
        return resp

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        resp = redirect(url_for("routes.login"))
        unset_jwt_cookies(resp)
        return resp

    app.register_blueprint(routes_bp)

    return app

def _recv_all_until_close(s: socket.socket, max_bytes: int) -> bytes:
    s.settimeout(10)
    out = bytearray()
    while len(out) < max_bytes:
        try:
            chunk = s.recv(min(4096, max_bytes - len(out)))
        except socket.timeout:
            break
        if not chunk:
            break
        out.extend(chunk)
    return bytes(out)

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=1337, use_reloader=False)
