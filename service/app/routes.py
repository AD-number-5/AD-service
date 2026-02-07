from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token,
    set_access_cookies,
    unset_jwt_cookies,
    jwt_required,
    get_jwt_identity,
)
from models import db, User, Art


routes_bp = Blueprint("routes", __name__)


@routes_bp.route("/register", methods=["GET", "POST"])
def register():
    # TODO:
    # - Validate input
    # - Check username uniqueness
    # - Hash password
    # - Store new user in SQLite via SQLAlchemy
    # - Return success / errors
    return jsonify({"status": "not implemented"}), 501


@routes_bp.route("/login", methods=["GET", "POST"])
def login():
    # TODO:
    # - Validate input
    # - Verify password hash
    # - Issue JWT and set HttpOnly cookie
    return jsonify({"status": "not implemented"}), 501


@routes_bp.route("/logout", methods=["POST"])
def logout():
    # TODO:
    # - Unset JWT cookie
    resp = jsonify({"status": "not implemented"})
    unset_jwt_cookies(resp)
    return resp, 501


@routes_bp.route("/", methods=["GET"])
@jwt_required()
def index():
    # TODO:
    # - Render "Hello {username}" page
    # - Show upload form
    _ = get_jwt_identity()
    return jsonify({"status": "not implemented"}), 501


@routes_bp.route("/upload", methods=["POST"])
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


@routes_bp.route("/gallery", methods=["GET"])
@jwt_required()
def gallery():
    # TODO:
    # - Fetch current user's arts
    # - Render gallery view
    return jsonify({"status": "not implemented"}), 501


@routes_bp.route("/media/<path:filename>", methods=["GET"])
@jwt_required()
def media(filename):
    # TODO:
    # - Ensure requesting user owns the file
    # - Serve file from storage
    return jsonify({"status": "not implemented"}), 501
