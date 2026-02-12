import os
import json
import socket
from datetime import timedelta
import secrets
from flask import Flask, redirect, url_for
from flask_jwt_extended import JWTManager, unset_jwt_cookies
from flask_sock import Sock
from models import db
from routes import routes_bp

NAME_LEN = 1000
IN_CHUNK = 42000
MAX_OUT = 42000

sock = Sock()

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

    # WebSocket
    sock.init_app(app)
    @sock.route("/ws/pixelize")
    def ws_pixelize(ws):
        meta_raw = ws.receive()
        meta = {}
        if isinstance(meta_raw, str) and meta_raw:
            meta = json.loads(meta_raw)

        filename = (meta.get("filename") or "img.bmp").encode("utf-8", "ignore")[:NAME_LEN]
        name_block = filename + b"\x00" * (NAME_LEN - len(filename))

        bmp = ws.receive()
        if not isinstance(bmp, (bytes, bytearray)):
            ws.send(json.dumps({"error": "second message must be binary BMP"}))
            return

        host = os.getenv("PIXELIZER_HOST", "pixelizer")
        port = int(os.getenv("PIXELIZER_PORT", "8080"))

        with socket.create_connection((host, port), timeout=5) as s:
            s.sendall(name_block)

            ok = s.recv(3)
            if not ok.startswith(b"OK"):
                ws.send(json.dumps({"error": f"pixelizer refused: {ok!r}"}))
                return

            bmp = bytes(bmp)
            for i in range(0, len(bmp), IN_CHUNK):
                s.sendall(bmp[i : i + IN_CHUNK])

            out_bmp = _recv_all_until_close(s, MAX_OUT)

        ws.send(out_bmp)

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
