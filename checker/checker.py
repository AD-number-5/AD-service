#!/usr/bin/env python3
import os
import io
from pathlib import Path
import sys
import re
import random
import string
import requests
from requests.sessions import Session

OK = 101
CORRUPT = 102
MUMBLE = 103
DOWN = 104
CHECKER_ERROR = 110

PORT = int(os.getenv("PORT", "1337"))
TIMEOUT = 10
FLAG_RE = re.compile(r"^[A-Z0-9]{31}=$")


def close(code, public="", private=""):
    if public:
        print(public)
    if private:
        print(private, file=sys.stderr)
    sys.exit(code)


def rnd_str(n=12):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))


def make_bmp_1x1():
    """Create a minimal valid BMP file 1x1 pixel (24-bit, black)."""
    header = b'BM'  
    header += (58).to_bytes(4, 'little')  
    header += (0).to_bytes(4, 'little')  
    header += (54).to_bytes(4, 'little')  
    dib = (40).to_bytes(4, 'little')  
    dib += (1).to_bytes(4, 'little')  
    dib += (1).to_bytes(4, 'little')  
    dib += (1).to_bytes(2, 'little')  
    dib += (24).to_bytes(2, 'little')  
    dib += (0).to_bytes(4, 'little')  
    dib += (4).to_bytes(4, 'little')  
    dib += (0).to_bytes(4, 'little')  
    dib += (0).to_bytes(4, 'little')  
    dib += (0).to_bytes(4, 'little')  
    dib += (0).to_bytes(4, 'little')  
    
    pixels = b'\x00\x00\x00\x00'
    return header + dib + pixels

def make_bmp(flag: str,
                                       final_size: int = 100,
                                       cols: int = 8,
                                       supersample: int = 8,
                                       thr: int = 160) -> bytes:
    from PIL import Image, ImageDraw, ImageFont
    import matplotlib.font_manager as fm

    prop = fm.FontProperties(family="DejaVu Sans Mono", weight="bold")
    font_path = fm.findfont(prop)

    rows = (len(flag) + cols - 1) // cols
    grid = [flag[i*cols:(i+1)*cols] for i in range(rows)]

    W = H = final_size * supersample
    img = Image.new("L", (W, H), 255)
    draw = ImageDraw.Draw(img)

    cell_w = W / cols
    cell_h = H / rows


    font_size = int(cell_h * 0.85)
    while font_size > 5:
        font = ImageFont.truetype(font_path, font_size)
        l, t, r, b = draw.textbbox((0, 0), "W", font=font)
        tw, th = r - l, b - t
        if tw <= cell_w * 0.90 and th <= cell_h * 0.90:
            break
        font_size -= 1

    stroke = max(1, supersample // 2)
    for y, line in enumerate(grid):
        for x, ch in enumerate(line):
            cx = (x + 0.5) * cell_w
            cy = (y + 0.5) * cell_h
            draw.text(
                (cx, cy),
                ch,
                font=font,
                fill=0,
                anchor="mm",
                stroke_width=stroke,
                stroke_fill=0,
            ) 

    img = img.resize((final_size, final_size), resample=Image.Resampling.LANCZOS)  

    img = img.point(lambda p: 255 if p > thr else 0)

    bio = io.BytesIO()
    img.convert("RGB").save(bio, format="BMP")
    return bio.getvalue()

def base_url(ip):
    return f"http://{ip}:{PORT}"


def register(sess: Session, ip: str, username: str, password: str):
    url = base_url(ip) + "/register"
    data = {"username": username, "password": password}
    try:
        resp = sess.post(url, data=data, timeout=TIMEOUT, allow_redirects=False)
    except requests.RequestException as e:
        close(DOWN, private=f"Register connection error: {e}")


def login(sess: Session, ip: str, username: str, password: str):
    url = base_url(ip) + "/login"
    data = {"username": username, "password": password}
    try:
        resp = sess.post(url, data=data, timeout=TIMEOUT, allow_redirects=False)
    except requests.RequestException as e:
        close(DOWN, private=f"Login connection error: {e}")
    if resp.status_code >= 400:
        close(MUMBLE, f"Login returned {resp.status_code}")


def update_profile(sess: Session, ip: str, description: str):
    url = base_url(ip) + "/profile"
    data = {"description": description}
    try:
        resp = sess.post(url, data=data, timeout=TIMEOUT, allow_redirects=False)
    except requests.RequestException as e:
        close(DOWN, private=f"Profile update connection error: {e}")
    if resp.status_code >= 400:
        close(MUMBLE, f"Profile update returned {resp.status_code}")


def get_index(sess: Session, ip: str) -> str:
    url = base_url(ip) + "/"
    try:
        resp = sess.get(url, timeout=TIMEOUT)
    except requests.RequestException as e:
        close(DOWN, private=f"GET / connection error: {e}")
    if resp.status_code != 200:
        close(MUMBLE, f"GET / returned {resp.status_code}")
    return resp.text


def upload_bmp(sess: Session, ip: str, bmp_data: bytes, filename: str = "test.bmp"):
    url = base_url(ip) + "/upload"
    files = {"file": (filename, bmp_data, "image/bmp")}
    try:
        resp = sess.post(url, files=files, timeout=TIMEOUT, allow_redirects=False)
    except requests.RequestException as e:
        close(DOWN, private=f"Upload connection error: {e}")
    if resp.status_code >= 400:
        close(MUMBLE, f"Upload returned {resp.status_code}")


def get_gallery(sess: Session, ip: str) -> list:
    url = base_url(ip) + "/gallery"
    try:
        resp = sess.get(url, timeout=TIMEOUT)
    except requests.RequestException as e:
        close(DOWN, private=f"Gallery connection error: {e}")
    if resp.status_code != 200:
        close(MUMBLE, f"Gallery returned {resp.status_code}")
    try:
        data = resp.json()
    except Exception:
        close(MUMBLE, "Gallery returned invalid JSON")
    items = data.get("items")
    if not isinstance(items, list):
        close(MUMBLE, "Gallery JSON missing 'items' list")
    return items


def get_media(sess: Session, ip: str, filename: str) -> bytes:
    url = base_url(ip) + f"/media/{filename}"
    try:
        resp = sess.get(url, timeout=TIMEOUT)
    except requests.RequestException as e:
        close(DOWN, private=f"Media connection error: {e}")
    if resp.status_code != 200:
        close(MUMBLE, f"Media {filename} returned {resp.status_code}")
    return resp.content


def action_check(ip: str):
    sess = requests.Session()
    username = "test_" + rnd_str(8)
    password = rnd_str(16)

    register(sess, ip, username, password)

    index_html = get_index(sess, ip)
    if username not in index_html:
        close(MUMBLE, "Username not found on main page after register")

    test_desc = "checker_test_" + rnd_str(10)
    update_profile(sess, ip, test_desc)

    index_html = get_index(sess, ip)
    if test_desc not in index_html:
        close(MUMBLE, "Description not found on main page after update")

    bmp_data = make_bmp_1x1()
    upload_bmp(sess, ip, bmp_data, "checker.bmp")

    items = get_gallery(sess, ip)
    if len(items) == 0:
        close(MUMBLE, "Gallery empty after upload")

    pixel_filename = items[0].get("pixel")
    if not pixel_filename:
        close(MUMBLE, "Gallery item missing 'pixel' field")

    media_data = get_media(sess, ip, pixel_filename)
    if len(media_data) == 0:
        close(MUMBLE, "Downloaded pixel image is empty")

    close(OK, "OK")


def action_put(ip: str, flag: str):
    sess = requests.Session()
    username = "user_" + rnd_str(8)
    password = rnd_str(16)
    register(sess, ip, username, password)

    update_profile(sess, ip, flag)

    index_html = get_index(sess, ip)
    if flag not in index_html:
        close(CORRUPT, "Flag not found after setting description")

    bmp_data = make_bmp(flag)  
    upload_bmp(sess, ip, bmp_data, filename=f"{rnd_str(10)}.bmp")

    close(OK, private=f"{username}:{password}")



def action_get(ip: str, flag_id: str, flag: str):
    if ":" not in flag_id:
        close(CHECKER_ERROR, "Invalid flag_id format (expected username:password)")
    username, password = flag_id.split(":", 1)

    sess = requests.Session()
    login(sess, ip, username, password)
    
    index_html = get_index(sess, ip)
    if flag not in index_html:
        close(CORRUPT, "Flag not found on user page")

    close(OK, "OK")


def main():
    if len(sys.argv) < 3:
        close(CHECKER_ERROR, "Usage: checker.py (check|put|get) IP [arguments]")

    cmd = sys.argv[1]
    ip = sys.argv[2]

    if cmd == "check":
        action_check(ip)
    elif cmd == "put":
        if len(sys.argv) < 5:
            close(CHECKER_ERROR, "PUT args: IP vuln_id flag")
        flag = sys.argv[4]
        if not FLAG_RE.match(flag):
            close(CHECKER_ERROR, "Invalid flag format")
        action_put(ip, flag)
    elif cmd == "get":
        if len(sys.argv) < 5:
            close(CHECKER_ERROR, "GET args: IP flag_id flag")
        flag_id = sys.argv[3]
        flag = sys.argv[4]
        if not FLAG_RE.match(flag):
            close(CHECKER_ERROR, "Invalid flag format")
        action_get(ip, flag_id, flag)
    else:
        close(CHECKER_ERROR, f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
