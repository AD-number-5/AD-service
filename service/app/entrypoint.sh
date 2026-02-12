#!/bin/sh
set -e

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$APP_DIR"

python3 - <<'PY'
from app import create_app
from models import db

app = create_app()
with app.app_context():
    db.create_all()
PY

exec python3 app.py
