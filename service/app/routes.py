from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash
from flask_jwt_extended import (
    create_access_token,
    set_access_cookies,
    unset_jwt_cookies,
    jwt_required,
    get_jwt_identity,
)
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Art


routes_bp = Blueprint("routes", __name__)


@routes_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    
    if not username or not password:
        return render_template("register.html", error="Username and password required"), 400
    
    if User.query.filter_by(username=username).first():
        return render_template("register.html", error="Username already exists"), 400
    
    user = User(
        username=username,
        password_hash=generate_password_hash(password),
        description=""
    )
    db.session.add(user)
    db.session.commit()
    
    access_token = create_access_token(identity=str(user.id))
    resp = redirect(url_for("routes.index"))
    set_access_cookies(resp, access_token)
    return resp


@routes_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    
    if not username or not password:
        return render_template("login.html", error="Username and password required"), 400
    
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return render_template("login.html", error="Invalid credentials"), 401
    
    access_token = create_access_token(identity=str(user.id))
    resp = redirect(url_for("routes.index"))
    set_access_cookies(resp, access_token)
    return resp


@routes_bp.route("/logout", methods=["POST"])
def logout():
    resp = redirect(url_for("routes.login"))
    unset_jwt_cookies(resp)
    return resp


@routes_bp.route("/", methods=["GET"])
@jwt_required()
def index():
    user_id = get_jwt_identity()
    user = User.query.get(int(user_id))
    if not user:
        resp = redirect(url_for("routes.login"))
        unset_jwt_cookies(resp)
        return resp
    return render_template("index.html", username=user.username, description=user.description)


@routes_bp.route("/profile", methods=["POST"])
@jwt_required()
def update_profile():
    user_id = get_jwt_identity()
    user = User.query.get(int(user_id))
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    description = request.form.get("description", "")
    user.description = description
    db.session.commit()
    
    return redirect(url_for("routes.index"))


@routes_bp.route("/upload", methods=["POST"])
@jwt_required()
def upload():
    # TODO:
    # - Загрузить изображение из формы и сохранить его в папку uploaded, а затем запустить процесс генерации пиксель-арта (можно просто скопировать файл в папку pixel и назвать его так же, как оригинал)
    return jsonify({"status": "not implemented"}), 501


@routes_bp.route("/gallery", methods=["GET"])
@jwt_required()
def gallery():
    # TODO:
    # - Получить список сгенерированных пиксель-артов текущего пользователя
    return jsonify({"status": "not implemented"}), 501


@routes_bp.route("/media/<path:filename>", methods=["GET"])
@jwt_required()
def media(filename):
    # TODO:
    # - Убедиться, что запрашивающий пользователь владеет артом и в ответе вернуть его содержимое
    return jsonify({"status": "not implemented"}), 501
