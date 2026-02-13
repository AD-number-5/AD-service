#!/usr/bin/env python3
import os
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
    # BMP header (14 bytes) + DIB header (40 bytes) = 54
    # Pixel data: 3 bytes BGR (0,0,0) + 1 byte padding (rows are 4-byte aligned)
    # Total: 54 + 4 = 58 bytes
    header = b'BM'  # Signature
    header += (58).to_bytes(4, 'little')  # File size
    header += (0).to_bytes(4, 'little')  # Reserved
    header += (54).to_bytes(4, 'little')  # Data offset
    dib = (40).to_bytes(4, 'little')  # DIB header size
    dib += (1).to_bytes(4, 'little')  # Width
    dib += (1).to_bytes(4, 'little')  # Height
    dib += (1).to_bytes(2, 'little')  # Planes
    dib += (24).to_bytes(2, 'little')  # Bits per pixel
    dib += (0).to_bytes(4, 'little')  # Compression (none)
    dib += (4).to_bytes(4, 'little')  # Image size (with padding)
    dib += (0).to_bytes(4, 'little')  # X pixels per meter
    dib += (0).to_bytes(4, 'little')  # Y pixels per meter
    dib += (0).to_bytes(4, 'little')  # Colors used
    dib += (0).to_bytes(4, 'little')  # Important colors
    # Pixel data: BGR (0,0,0) + 1 byte padding
    pixels = b'\x00\x00\x00\x00'
    return header + dib + pixels


def base_url(ip):
    return f"http://{ip}:{PORT}"


def register(sess: Session, ip: str, username: str, password: str):
    url = base_url(ip) + "/register"
    data = {"username": username, "password": password}
    try:
        resp = sess.post(url, data=data, timeout=TIMEOUT, allow_redirects=False)
    except requests.RequestException as e:
        close(DOWN, private=f"Register connection error: {e}")
    # Expecting 302 redirect with Set-Cookie
    if resp.status_code != 302:
        close(MUMBLE, f"Register returned {resp.status_code}, expected 302")
    # Follow redirect manually to get the cookie (session will handle)
    redirect_url = resp.headers.get("Location")
    if not redirect_url:
        close(MUMBLE, "Register: no Location header")
    # GET the redirect to actually login
    try:
        sess.get(base_url(ip) + redirect_url, timeout=TIMEOUT)
    except requests.RequestException as e:
        close(DOWN, private=f"Register redirect failed: {e}")


def login(sess: Session, ip: str, username: str, password: str):
    url = base_url(ip) + "/login"
    data = {"username": username, "password": password}
    try:
        resp = sess.post(url, data=data, timeout=TIMEOUT, allow_redirects=False)
    except requests.RequestException as e:
        close(DOWN, private=f"Login connection error: {e}")
    if resp.status_code != 302:
        close(MUMBLE, f"Login returned {resp.status_code}, expected 302")
    redirect_url = resp.headers.get("Location")
    if not redirect_url:
        close(MUMBLE, "Login: no Location header")
    try:
        sess.get(base_url(ip) + redirect_url, timeout=TIMEOUT)
    except requests.RequestException as e:
        close(DOWN, private=f"Login redirect failed: {e}")


def update_profile(sess: Session, ip: str, description: str):
    url = base_url(ip) + "/profile"
    data = {"description": description}
    try:
        resp = sess.post(url, data=data, timeout=TIMEOUT, allow_redirects=False)
    except requests.RequestException as e:
        close(DOWN, private=f"Profile update connection error: {e}")
    if resp.status_code != 302:
        close(MUMBLE, f"Profile update returned {resp.status_code}, expected 302")
    # Follow redirect to index
    redirect_url = resp.headers.get("Location")
    if not redirect_url:
        close(MUMBLE, "Profile update: no Location header")
    try:
        sess.get(base_url(ip) + redirect_url, timeout=TIMEOUT)
    except requests.RequestException as e:
        close(DOWN, private=f"Profile redirect failed: {e}")


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
    if resp.status_code != 302:
        close(MUMBLE, f"Upload returned {resp.status_code}, expected 302")
    redirect_url = resp.headers.get("Location")
    if not redirect_url:
        close(MUMBLE, "Upload: no Location header")
    try:
        sess.get(base_url(ip) + redirect_url, timeout=TIMEOUT)
    except requests.RequestException as e:
        close(DOWN, private=f"Upload redirect failed: {e}")


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

    # Check authentication
    index_html = get_index(sess, ip)
    if username not in index_html:
        close(MUMBLE, "Username not found on main page after register")

    # Update profile with test description
    test_desc = "checker_test_" + rnd_str(10)
    update_profile(sess, ip, test_desc)

    # Verify description appears on main page
    index_html = get_index(sess, ip)
    if test_desc not in index_html:
        close(MUMBLE, "Description not found on main page after update")

    # Upload a test BMP
    bmp_data = make_bmp_1x1()
    upload_bmp(sess, ip, bmp_data, "checker.bmp")

    # Check gallery for new art
    items = get_gallery(sess, ip)
    if len(items) == 0:
        close(MUMBLE, "Gallery empty after upload")

    # Get the latest pixel filename (assuming it's the last one)
    pixel_filename = items[0].get("pixel")
    if not pixel_filename:
        close(MUMBLE, "Gallery item missing 'pixel' field")

    # Try to download the pixel image
    media_data = get_media(sess, ip, pixel_filename)
    if len(media_data) == 0:
        close(MUMBLE, "Downloaded pixel image is empty")

    close(OK, "OK")


def action_put(ip: str, flag: str):
    sess = requests.Session()
    username = "user_" + rnd_str(8)
    password = rnd_str(16)
    register(sess, ip, username, password)

    # Set flag as description
    update_profile(sess, ip, flag)

    # Verify that flag is present on main page
    index_html = get_index(sess, ip)
    if flag not in index_html:
        close(CORRUPT, "Flag not found after setting description")

    # Return credentials as flag_id (private)
    close(OK, private=f"{username}:{password}")


def action_get(ip: str, flag_id: str, flag: str):
    if ":" not in flag_id:
        close(CHECKER_ERROR, "Invalid flag_id format (expected username:password)")
    username, password = flag_id.split(":", 1)

    sess = requests.Session()
    login(sess, ip, username, password)

    # Check main page for flag
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
