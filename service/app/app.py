from datetime import timedelta
import secrets
from flask import Flask
from flask_jwt_extended import JWTManager
from models import db
from routes import routes_bp


def create_app():
    app = Flask(__name__)

    # Config
    app.config["SECRET_KEY"] = secrets.token_hex(32)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite3"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["JWT_SECRET_KEY"] = secrets.token_hex(32)
    app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
    app.config["JWT_ACCESS_COOKIE_NAME"] = "access_token"
    app.config["JWT_COOKIE_SECURE"] = False
    app.config["JWT_COOKIE_CSRF_PROTECT"] = True
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=12)

    db.init_app(app)
    JWTManager(app)

    app.register_blueprint(routes_bp)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000)
