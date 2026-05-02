# iedocs

Минимальный, но рабочий MVP ЭДО:
- `backend` на Rust (`axum` + `sqlx`)
- `frontend` на Next.js
- `nginx` как reverse proxy
- `postgres` для хранения PDF (в зашифрованном виде), метаданных, индекса поиска и шаблонов

## Что умеет сейчас

1. Логин по JWT.
2. Загрузка PDF-сканов.
3. Шифрование файлов на уровне приложения (AES-256-GCM) перед записью в БД.
4. Индексация текста:
   - извлечение встроенного текста из PDF;
   - OCR fallback для сканов (`pdftoppm` + `tesseract`, ru+en).
5. Поиск по документам (PostgreSQL full-text + поиск по заголовку).
6. Загрузка DOCX-шаблонов с placeholders `{{...}}`.
7. Генерация документов из шаблонов:
   - `DOCX` (нативно)
   - `PDF` (через LibreOffice headless)
8. Удаление документов и шаблонов.

## Быстрый старт

1. Проверь `backend/.env.example` и при необходимости поменяй значения.
   - для корректной кириллицы в генераторе и стиля Times New Roman положи TTF-файл в:
     `backend/fonts/Times New Roman.ttf`
2. Запусти:

```bash
docker compose up --build
```

3. Открой:
   - UI: `http://localhost`
   - API health: `http://localhost/api/healthz`

## Безопасность (что уже учтено)

- JWT с ограниченным TTL.
- Пароль администратора хранится как `argon2` hash.
- CORS только для указанного origin.
- Ограничение размера request body.
- Проверка magic bytes PDF (`%PDF-`).
- Шифрование файлов перед записью в PostgreSQL.
- SHA-256 checksum для контроля целостности.
- NGINX security headers + базовый rate limit.
- В генерации PDF отключён JavaScript в шаблонах.

## Важные env-переменные

`backend/.env.example`:
- `DATABASE_URL`
- `ADMIN_USER`
- `ADMIN_PASSWORD_HASH`
- `JWT_SECRET`
- `DOCS_ENCRYPTION_KEY` (base64, ровно 32 байта после декодирования)
- `MAX_UPLOAD_MB`
- `CORS_ORIGIN`
- `PDF_FONT_PATH` (`/app/fonts/Times New Roman.ttf`)
- `PDF_FONT_SIZE_PT` (`14`)
- `LIBREOFFICE_BIN` (`soffice`)

## API (кратко)

- `POST /api/v1/auth/login`
- `POST /api/v1/documents` (multipart: `title`, `file`)
- `GET /api/v1/documents?q=...`
- `DELETE /api/v1/documents/:id`
- `GET /api/v1/documents/:id/download`
- `GET /api/v1/templates`
- `POST /api/v1/templates`
- `POST /api/v1/templates/docx` (multipart: `name`, `file`)
- `DELETE /api/v1/templates/:id`
- `POST /api/v1/templates/:id/render`

## Что стоит добавить следующим шагом

1. Роли и пользователи (RBAC) вместо single-admin.
2. Аудит действий (кто/когда скачал, изменил, удалил).
3. Антивирусный скан и DLP-проверки.
4. Версионирование документов.
5. Бэкапы + key rotation для ключа шифрования.
