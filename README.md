# Pixel Art Service

Учебный Attack-Defense сервис для загрузки изображений и генерации пиксель-арта. Состоит из веб-приложения на Flask и отдельного пикселизатора.

## Описание

Пользователи могут:
- Регистрироваться и входить в систему
- Заполнять описание профиля
- Загружать изображения в формате BMP и получать пиксель-арт
- Просматривать свою галерею

**Флаги размещаются** в описании профиля и внутри загружаемых BMP изображений (через чекер).

## Архитектура

### Backend (Python)
- **Фреймворк**: Flask
- **Аутентификация**: JWT cookies (Flask-JWT-Extended)
- **БД**: SQLite через SQLAlchemy
- **Хранилища файлов**:
  - `uploaded/` — оригинальные BMP
  - `media/` — пикселизированные BMP

### Pixelizer
- Отдельный сервис, работающий по TCP
- Принимает имя файла фиксированной длины и байты BMP
- Возвращает пикселизированный BMP

## Запуск

### Docker (рекомендуется для AD)

```bash
cd service
docker-compose up --build
```

Сервис будет доступен на http://localhost:1337 (или на порту из переменной `PORT`).

## Дисклеймер по Tesseract (для эксплоитов)

**Важно:** для работы эксплоита требуется установленный бинарник `tesseract`, а не только Python-библиотека `pytesseract`.

### Установка

#### Debian/Ubuntu

```bash
sudo apt update
sudo apt install -y tesseract-ocr
```

#### Arch Linux

```bash
sudo pacman -S tesseract
```

#### Fedora

```bash
sudo dnf install -y tesseract
```

#### macOS (Homebrew)

```bash
brew install tesseract
```

#### Windows (Chocolatey)

```powershell
choco install tesseract
```

### Проверка

```bash
tesseract --version
```

Если команда выводит версию, значит бинарник установлен корректно.

## Структура проекта

```text
service/
├── app/
│   ├── app.py
│   ├── Dockerfile
│   ├── entrypoint.sh
│   ├── models.py
│   ├── requirements.txt
│   ├── routes.py
│   └── templates/
│       ├── base.html
│       ├── index.html
│       ├── login.html
│       └── register.html
├── docker-compose.yaml
└── pixelizer/
  ├── Dockerfile
  └── pixelizer

checker/
├── checker.py
└── requirements.txt

sploit1/
├── requirements.txt
└── sploit.py

sploit2/
├── requirements.txt
└── sploit.py

sploit3/
├── requirements.txt
└── sploit.py
```

## API Endpoints

Публичные

  GET / — главная страница

  GET /register — форма регистрации

  POST /register — регистрация

  GET /login — форма входа

  POST /login — вход

Требуют авторизации (JWT)

  POST /logout — выход

  POST /profile — обновить описание профиля

  POST /upload — загрузить BMP и получить пиксель-арт

  GET /gallery — список загруженных изображений (JSON)

  GET /media/<filename> — получить пиксель-арт изображение
