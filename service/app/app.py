from datetime import timedelta
from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    set_access_cookies,
    unset_jwt_cookies,
    jwt_required,
    get_jwt_identity,
)
from models import db, User, Art


def create_app():
    app = Flask(__name__)

    # Config
    app.config["SECRET_KEY"] = "CHANGE_ME"
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite3"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["JWT_SECRET_KEY"] = "CHANGE_ME_TOO"
    app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
    app.config["JWT_ACCESS_COOKIE_NAME"] = "access_token"
    app.config["JWT_COOKIE_SECURE"] = False
    app.config["JWT_COOKIE_CSRF_PROTECT"] = True
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=12)

    db.init_app(app)
    JWTManager(app)

    @app.route("/register", methods=["GET", "POST"])
    def register():
        # TODO:
        # - Validate input
        # - Check username uniqueness
        # - Hash password
        # - Store new user in SQLite via SQLAlchemy
        # - Return success / errors
        return jsonify({"status": "not implemented"}), 501

    @app.route("/login", methods=["GET", "POST"])
    def login():
        # TODO:
        # - Validate input
        # - Verify password hash
        # - Issue JWT and set HttpOnly cookie
        return jsonify({"status": "not implemented"}), 501

    @app.route("/logout", methods=["POST"])
    def logout():
        # TODO:
        # - Unset JWT cookie
        resp = jsonify({"status": "not implemented"})
        unset_jwt_cookies(resp)
        return resp, 501

    @app.route("/", methods=["GET"])
    @jwt_required()
    def index():
        # TODO:
        # - Render "Hello {username}" page
        # - Show upload form
        _ = get_jwt_identity()
        return jsonify({"status": "not implemented"}), 501

    @app.route("/upload", methods=["POST"])
    @jwt_required()
    def upload():
        # TODO:
        # - Accept file
        # - Validate size/type
        # - Save original
        # - Run pixelization via subprocess
        # - Save result
        # - Store Art record
        return jsonify({"status": "not implemented"}), 501

    @app.route("/gallery", methods=["GET"])
    @jwt_required()
    def gallery():
        # TODO:
        # - Fetch current user's arts
        # - Render gallery view
        return jsonify({"status": "not implemented"}), 501

    @app.route("/media/<path:filename>", methods=["GET"])
    @jwt_required()
    def media(filename):
        # TODO:
        # - Ensure requesting user owns the file
        # - Serve file from storage
        return jsonify({"status": "not implemented"}), 501

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000)
