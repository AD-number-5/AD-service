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
    # Реализовать регистрацию пользователя и выдачу JWT в cookie
    return jsonify({"status": "not implemented"}), 501


@routes_bp.route("/login", methods=["GET", "POST"])
def login():
    # TODO:
    # Проверить хэш пароля и выдать JWT в cookie
    return jsonify({"status": "not implemented"}), 501


@routes_bp.route("/logout", methods=["POST"])
def logout():
    # TODO:
    # Очистить cookie
    resp = jsonify({"status": "not implemented"})
    unset_jwt_cookies(resp)
    return resp, 501


@routes_bp.route("/", methods=["GET"])
@jwt_required()
def index():
    # TODO:
    # Главная страница. В зависимости от того, 
    # аутентифицирован ли пользователь, пепенаправить на вход или показать главную страницу 
    _ = get_jwt_identity()
    return jsonify({"status": "not implemented"}), 501


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
