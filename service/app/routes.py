import os
import socket
from flask import Blueprint, render_template_string, request, jsonify, render_template, redirect, url_for, flash, send_from_directory
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

MAX_IMAGE_SIZE = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {"bmp"}
NAME_LEN = 1000
IN_CHUNK = 42000
MAX_OUT = 42000


def _recv_all_until_close(sock: socket.socket, max_bytes: int) -> bytes:
    sock.settimeout(10)
    out = bytearray()
    while len(out) < max_bytes:
        try:
            chunk = sock.recv(min(4096, max_bytes - len(out)))
        except socket.timeout:
            break
        if not chunk:
            break
        out.extend(chunk)
    return bytes(out)


def _pixelize_via_service(filename: str, bmp_data: bytes) -> bytes:
    host = os.getenv("PIXELIZER_HOST", "pixelizer")
    port = int(os.getenv("PIXELIZER_PORT", "8080"))

    name_bytes = filename.encode("utf-8", "ignore")[:NAME_LEN]
    name_block = name_bytes + b"\x00" * (NAME_LEN - len(name_bytes))

    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(name_block)

        ok = sock.recv(3)
        if not ok.startswith(b"OK"):
            raise RuntimeError(f"pixelizer refused: {ok!r}")

        for i in range(0, len(bmp_data), IN_CHUNK):
            sock.sendall(bmp_data[i : i + IN_CHUNK])

        out_bmp = _recv_all_until_close(sock, MAX_OUT)

    if not out_bmp or out_bmp.startswith(b"E:"):
        raise RuntimeError("pixelizer failed")

    return out_bmp

def secure_filename(filename: str) -> str:
    forbidden_chars = [
        " ", "\t", "\n", "\r",
        "\"", "'", "`",
        "/", "\\",
        ":", ";", ",", ".",
        "<", ">", "(", ")",
        "[", "]", "{", "}",
        "!", "?", "*", "#",
        "%", "&", "@", "^",
        "~", "+",
    ]
    for ch in forbidden_chars:
        filename = filename.replace(ch, "")
    return filename


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
@jwt_required(optional=True)
def index():
    user_id = get_jwt_identity()
    if not user_id:
        return redirect(url_for("routes.login"))
    user = User.query.get(int(user_id))
    if not user:
        resp = redirect(url_for("routes.login"))
        unset_jwt_cookies(resp)
        return resp
    arts = Art.query.filter_by(user_id=user.id).order_by(Art.created_at.desc()).all()
    wrap = render_template_string(f'пользователь с ником {user.username}')
    return render_template(
        "index.html",
        username_wrap=wrap,
        description=user.description,
        arts=arts,
    )


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
    user_id = get_jwt_identity()
    file = request.files.get("file")
    raw_filename = file.filename if file else ""
    safe_raw_filename = os.path.basename(raw_filename)
    filename = secure_filename(safe_raw_filename) if file else None
    art_id_raw = request.form.get("art_id", "").strip()

    base_dir = os.path.dirname(__file__)
    upload_dir = os.path.join(base_dir, "uploaded")
    media_dir = os.path.join(base_dir, "media")
    os.makedirs(upload_dir, exist_ok=True)
    os.makedirs(media_dir, exist_ok=True)

    if art_id_raw and not art_id_raw.isdigit():
        flash("ID должен быть числом")
        return redirect(url_for("routes.index"))

    if not art_id_raw:
        max_id = 0
        for name in os.listdir(upload_dir):
            base, ext = os.path.splitext(name)
            if base.isdigit() and ext.lstrip(".").lower() in ALLOWED_EXTENSIONS:
                max_id = max(max_id, int(base))
        art_id_raw = str(max_id + 1)

    existing_name = None
    for name in os.listdir(upload_dir):
        base, ext = os.path.splitext(name)
        if base == art_id_raw and ext.lstrip(".").lower() in ALLOWED_EXTENSIONS:
            existing_name = name
            break

    if existing_name:
        original_name = existing_name
        original_path = os.path.join(upload_dir, original_name)
        with open(original_path, "rb") as f:
            pixel_data = f.read()
    else:
        if not file or not filename:
            flash("Файл не выбран")
            return redirect(url_for("routes.index"))
        ext = safe_raw_filename.rsplit(".", 1)[-1].lower() if "." in safe_raw_filename else ""
        if ext not in ALLOWED_EXTENSIONS:
            flash("Неподдерживаемый тип файла")
            return redirect(url_for("routes.index"))
        data = file.read()
        if len(data) > MAX_IMAGE_SIZE:
            flash("Размер файла превышает 5 МБ")
            return redirect(url_for("routes.index"))

        original_name = f"{art_id_raw}.{ext}"
        if len(original_name.encode("utf-8")) > 512:
            flash("Имя файла слишком длинное")
            return redirect(url_for("routes.index"))
        temp_path = os.path.join(upload_dir, safe_raw_filename)
        with open(temp_path, "wb") as f:
            f.write(data)
        try:
            pixel_data = _pixelize_via_service(safe_raw_filename, data)
        except (OSError, RuntimeError, ValueError) as exc:
            flash(f"Ошибка пикселизации: {exc}")
            return redirect(url_for("routes.index"))

        final_path = os.path.join(upload_dir, original_name)
        if temp_path != final_path:
            os.replace(temp_path, final_path)

    pixel_name = f"pixel_{original_name}"
    pixel_path = os.path.join(media_dir, pixel_name)
    with open(pixel_path, "wb") as f:
        f.write(pixel_data)

    art = Art(
        user_id=int(user_id),
        filename_original=original_name,
        filename_pixel=pixel_name,
    )
    db.session.add(art)
    db.session.commit()

    flash("Изображение успешно загружено")
    return {"filename": pixel_name}


@routes_bp.route("/gallery", methods=["GET"])
@jwt_required()
def gallery():
    user_id = get_jwt_identity()
    user = User.query.get(int(user_id))
    if not user:
        return jsonify({"error": "User not found"}), 404

    arts = Art.query.filter_by(user_id=user.id).order_by(Art.created_at.desc()).all()
    return jsonify(
        {
            "items": [
                {
                    "id": art.id,
                    "original": art.filename_original,
                    "pixel": art.filename_pixel,
                    "created_at": art.created_at.isoformat(),
                }
                for art in arts
            ]
        }
    )


@routes_bp.route("/media/<path:filename>", methods=["GET"])
@jwt_required()
def media(filename):
    user_id = get_jwt_identity()
    user = User.query.get(int(user_id))
    if not user:
        return jsonify({"error": "User not found"}), 404

    art = Art.query.filter_by(user_id=user.id, filename_pixel=filename).first()
    if not art:
        return jsonify({"error": "Forbidden"}), 403

    media_dir = os.path.join(os.path.dirname(__file__), "media")
    return send_from_directory(media_dir, filename)
