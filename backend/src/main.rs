use std::cmp::min;
use std::fs::File;
use std::io::{BufWriter, Cursor, Read, Write};
use std::process::Command as StdCommand;
use std::sync::Arc;
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use argon2::password_hash::PasswordHash;
use argon2::{Argon2, PasswordVerifier};
use async_trait::async_trait;
use axum::body::Body;
use axum::extract::{FromRef, FromRequestParts, Multipart, Path, Query, State};
use axum::http::header::{AUTHORIZATION, CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use handlebars::Handlebars;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use printpdf::{Mm, PdfDocument};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{FromRow, PgPool};
use tempfile::tempdir;
use thiserror::Error;
use tokio::task;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};
use uuid::Uuid;
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY,
    title TEXT NOT NULL,
    filename TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    file_size BIGINT NOT NULL,
    ciphertext BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    checksum BYTEA NOT NULL,
    extracted_text TEXT NOT NULL DEFAULT '',
    uploaded_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_documents_created_at ON documents (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_documents_text_fts ON documents USING GIN (to_tsvector('simple', extracted_text));

CREATE TABLE IF NOT EXISTS templates (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    body TEXT NOT NULL DEFAULT '',
    template_type TEXT NOT NULL DEFAULT 'text',
    docx_ciphertext BYTEA,
    docx_nonce BYTEA,
    docx_filename TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_templates_updated_at ON templates (updated_at DESC);

ALTER TABLE templates
    ADD COLUMN IF NOT EXISTS template_type TEXT NOT NULL DEFAULT 'text';
ALTER TABLE templates
    ADD COLUMN IF NOT EXISTS docx_ciphertext BYTEA;
ALTER TABLE templates
    ADD COLUMN IF NOT EXISTS docx_nonce BYTEA;
ALTER TABLE templates
    ADD COLUMN IF NOT EXISTS docx_filename TEXT;
ALTER TABLE templates
    ALTER COLUMN body SET DEFAULT '';
"#;

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    cfg: AppConfig,
    jwt_encoding: EncodingKey,
    jwt_decoding: DecodingKey,
    encryption_key: [u8; 32],
    handlebars: Arc<Handlebars<'static>>,
}

#[derive(Clone)]
struct AppConfig {
    database_url: String,
    bind_addr: String,
    cors_origin: String,
    max_upload_bytes: usize,
    admin_user: String,
    admin_password_hash: Option<String>,
    admin_password: Option<String>,
    jwt_secret: String,
    jwt_ttl_minutes: i64,
    ocr_lang: String,
    pdf_font_path: String,
    pdf_font_fallback_path: String,
    pdf_font_size_pt: f32,
    libreoffice_bin: String,
}

impl AppConfig {
    fn from_env() -> Result<Self, ApiError> {
        let database_url = required_env("DATABASE_URL")?;
        let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_owned());
        let cors_origin =
            std::env::var("CORS_ORIGIN").unwrap_or_else(|_| "http://localhost".to_owned());
        let max_upload_mb = std::env::var("MAX_UPLOAD_MB")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(25);
        let admin_user = std::env::var("ADMIN_USER").unwrap_or_else(|_| "admin".to_owned());
        let admin_password_hash = std::env::var("ADMIN_PASSWORD_HASH")
            .ok()
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty());
        let admin_password = std::env::var("ADMIN_PASSWORD")
            .ok()
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty());
        if admin_password_hash.is_none() && admin_password.is_none() {
            return Err(ApiError::Internal(
                "set ADMIN_PASSWORD_HASH or ADMIN_PASSWORD".to_owned(),
            ));
        }
        let jwt_secret = required_env("JWT_SECRET")?;
        let jwt_ttl_minutes = std::env::var("JWT_TTL_MINUTES")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(60);
        let ocr_lang = std::env::var("OCR_LANG").unwrap_or_else(|_| "rus+eng".to_owned());
        let pdf_font_path = std::env::var("PDF_FONT_PATH")
            .unwrap_or_else(|_| "/app/fonts/Times New Roman.ttf".to_owned());
        let pdf_font_fallback_path = std::env::var("PDF_FONT_FALLBACK_PATH")
            .unwrap_or_else(|_| "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf".to_owned());
        let pdf_font_size_pt = std::env::var("PDF_FONT_SIZE_PT")
            .ok()
            .and_then(|v| v.parse::<f32>().ok())
            .filter(|v| *v >= 8.0 && *v <= 40.0)
            .unwrap_or(14.0);
        let libreoffice_bin =
            std::env::var("LIBREOFFICE_BIN").unwrap_or_else(|_| "soffice".to_owned());

        Ok(Self {
            database_url,
            bind_addr,
            cors_origin,
            max_upload_bytes: max_upload_mb * 1024 * 1024,
            admin_user,
            admin_password_hash,
            admin_password,
            jwt_secret,
            jwt_ttl_minutes,
            ocr_lang,
            pdf_font_path,
            pdf_font_fallback_path,
            pdf_font_size_pt,
            libreoffice_bin,
        })
    }
}

#[derive(Debug, Error)]
enum ApiError {
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self {
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = Json(json!({ "error": self.to_string() }));
        (status, body).into_response()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iat: usize,
    exp: usize,
}

#[derive(Clone, Debug)]
struct AuthenticatedUser {
    username: String,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let app = AppState::from_ref(state);
        let header_value = parts
            .headers
            .get(AUTHORIZATION)
            .ok_or_else(|| ApiError::Unauthorized("missing Authorization header".to_owned()))?;
        let header_str = header_value
            .to_str()
            .map_err(|_| ApiError::Unauthorized("invalid Authorization header".to_owned()))?;
        let token = header_str
            .strip_prefix("Bearer ")
            .ok_or_else(|| ApiError::Unauthorized("expected Bearer token".to_owned()))?;
        let decoded =
            decode::<Claims>(token, &app.jwt_decoding, &Validation::new(Algorithm::HS256))
                .map_err(|_| ApiError::Unauthorized("invalid or expired token".to_owned()))?;

        Ok(Self {
            username: decoded.claims.sub,
        })
    }
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    access_token: String,
    token_type: String,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, FromRow)]
struct DocumentListRow {
    id: Uuid,
    title: String,
    filename: String,
    file_size: i64,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct DocumentListResponse {
    items: Vec<DocumentListRow>,
}

#[derive(Debug, Deserialize)]
struct SearchQuery {
    q: Option<String>,
    limit: Option<i64>,
}

#[derive(Debug, FromRow)]
struct DownloadRow {
    filename: String,
    mime_type: String,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct TemplateUpsertRequest {
    name: String,
    body: String,
}

#[derive(Debug, Serialize, FromRow)]
struct TemplateRow {
    id: Uuid,
    name: String,
    template_type: String,
    docx_filename: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct TemplateSourceRow {
    name: String,
    body: String,
    template_type: String,
    docx_ciphertext: Option<Vec<u8>>,
    docx_nonce: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
struct TemplateRenderRequest {
    values: Value,
    title: Option<String>,
    save_as_document: Option<bool>,
    output_format: Option<String>,
}

#[derive(Debug, Serialize)]
struct DeleteResult {
    deleted: bool,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=info".into()),
        )
        .init();

    if let Err(err) = run().await {
        error!("{err}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), ApiError> {
    let cfg = AppConfig::from_env()?;
    let encryption_key = load_encryption_key()?;

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&cfg.database_url)
        .await
        .map_err(|e| ApiError::Internal(format!("cannot connect to database: {e}")))?;

    sqlx::raw_sql(SCHEMA_SQL)
        .execute(&pool)
        .await
        .map_err(|e| ApiError::Internal(format!("cannot init schema: {e}")))?;

    let state = AppState {
        pool,
        cfg: cfg.clone(),
        jwt_encoding: EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
        jwt_decoding: DecodingKey::from_secret(cfg.jwt_secret.as_bytes()),
        encryption_key,
        handlebars: Arc::new(Handlebars::new()),
    };

    let cors_origin = HeaderValue::from_str(&cfg.cors_origin)
        .map_err(|e| ApiError::Internal(format!("invalid CORS_ORIGIN: {e}")))?;

    let app = Router::new()
        .route("/api/healthz", get(healthz))
        .route("/api/v1/auth/login", post(login))
        .route(
            "/api/v1/documents",
            post(upload_document).get(search_documents),
        )
        .route(
            "/api/v1/documents/:id",
            axum::routing::delete(delete_document),
        )
        .route("/api/v1/documents/:id/download", get(download_document))
        .route(
            "/api/v1/templates",
            get(list_templates).post(upsert_template),
        )
        .route("/api/v1/templates/docx", post(upload_docx_template))
        .route(
            "/api/v1/templates/:id",
            axum::routing::delete(delete_template),
        )
        .route("/api/v1/templates/:id/render", post(render_template))
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(cfg.max_upload_bytes))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(45),
        ))
        .layer(
            CorsLayer::new()
                .allow_origin(cors_origin)
                .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to bind {}: {e}", cfg.bind_addr)))?;

    info!("backend listening on {}", cfg.bind_addr);
    axum::serve(listener, app.into_make_service())
        .await
        .map_err(|e| ApiError::Internal(format!("server error: {e}")))?;

    Ok(())
}

async fn healthz() -> impl IntoResponse {
    Json(json!({ "status": "ok", "service": "iedocs-backend" }))
}

async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    if req.username != state.cfg.admin_user {
        return Err(ApiError::Unauthorized("invalid credentials".to_owned()));
    }

    if let Some(hash_str) = &state.cfg.admin_password_hash {
        let hash = PasswordHash::new(hash_str)
            .map_err(|e| ApiError::Internal(format!("invalid ADMIN_PASSWORD_HASH: {e}")))?;
        Argon2::default()
            .verify_password(req.password.as_bytes(), &hash)
            .map_err(|_| ApiError::Unauthorized("invalid credentials".to_owned()))?;
    } else if state.cfg.admin_password.as_deref() != Some(req.password.as_str()) {
        return Err(ApiError::Unauthorized("invalid credentials".to_owned()));
    } else {
        warn!("using plain ADMIN_PASSWORD, switch to ADMIN_PASSWORD_HASH for production");
    }

    let now = Utc::now();
    let expires_at = now + ChronoDuration::minutes(state.cfg.jwt_ttl_minutes);
    let claims = Claims {
        sub: req.username,
        iat: now.timestamp() as usize,
        exp: expires_at.timestamp() as usize,
    };

    let token = encode(&Header::default(), &claims, &state.jwt_encoding)
        .map_err(|e| ApiError::Internal(format!("failed to sign JWT: {e}")))?;

    Ok(Json(LoginResponse {
        access_token: token,
        token_type: "Bearer".to_owned(),
        expires_at,
    }))
}

async fn upload_document(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    mut multipart: Multipart,
) -> Result<Json<DocumentListRow>, ApiError> {
    let mut title: Option<String> = None;
    let mut file_name: Option<String> = None;
    let mut file_bytes: Option<Vec<u8>> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::BadRequest(format!("invalid multipart payload: {e}")))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        if name == "title" {
            let text = field
                .text()
                .await
                .map_err(|e| ApiError::BadRequest(format!("invalid title: {e}")))?;
            if !text.trim().is_empty() {
                title = Some(text.trim().to_owned());
            }
            continue;
        }
        if name == "file" {
            file_name = field.file_name().map(ToOwned::to_owned);
            let bytes = field
                .bytes()
                .await
                .map_err(|e| ApiError::BadRequest(format!("invalid file bytes: {e}")))?;
            file_bytes = Some(bytes.to_vec());
        }
    }

    let file = file_bytes.ok_or_else(|| ApiError::BadRequest("file is required".to_owned()))?;
    if file.len() > state.cfg.max_upload_bytes {
        return Err(ApiError::BadRequest(format!(
            "file too large, max {} bytes",
            state.cfg.max_upload_bytes
        )));
    }
    if !is_pdf(&file) {
        return Err(ApiError::BadRequest(
            "only PDF files are supported".to_owned(),
        ));
    }

    let original_filename = file_name.unwrap_or_else(|| "document.pdf".to_owned());
    let document_title = title.unwrap_or_else(|| original_filename.clone());

    let mut extracted_text = try_extract_pdf_text(&file).unwrap_or_default();
    if extracted_text.trim().is_empty() {
        warn!("no embedded text, trying OCR for {}", original_filename);
        extracted_text = run_ocr(&file, &state.cfg.ocr_lang).await?;
    }
    let indexed_text = normalize_text_for_index(&extracted_text);
    let (nonce, ciphertext) = encrypt_bytes(&state.encryption_key, &file)?;
    let checksum = sha256(&file);
    let id = Uuid::new_v4();

    let row = sqlx::query_as::<_, DocumentListRow>(
        r#"
        INSERT INTO documents (
            id, title, filename, mime_type, file_size,
            ciphertext, nonce, checksum, extracted_text, uploaded_by
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING id, title, filename, file_size, created_at
        "#,
    )
    .bind(id)
    .bind(document_title)
    .bind(original_filename)
    .bind("application/pdf")
    .bind(file.len() as i64)
    .bind(ciphertext)
    .bind(nonce)
    .bind(checksum)
    .bind(indexed_text)
    .bind(user.username)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(format!("failed to store document: {e}")))?;

    Ok(Json(row))
}

async fn search_documents(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    Query(query): Query<SearchQuery>,
) -> Result<Json<DocumentListResponse>, ApiError> {
    let limit = min(query.limit.unwrap_or(25).max(1), 100);
    let rows = if let Some(q) = query.q.and_then(clean_search_query) {
        sqlx::query_as::<_, DocumentListRow>(
            r#"
            SELECT id, title, filename, file_size, created_at
            FROM documents
            WHERE
                to_tsvector('simple', extracted_text) @@ plainto_tsquery('simple', $1)
                OR title ILIKE '%' || $1 || '%'
            ORDER BY
                ts_rank(to_tsvector('simple', extracted_text), plainto_tsquery('simple', $1)) DESC,
                created_at DESC
            LIMIT $2
            "#,
        )
        .bind(q)
        .bind(limit)
        .fetch_all(&state.pool)
        .await
        .map_err(|e| ApiError::Internal(format!("search failed: {e}")))?
    } else {
        sqlx::query_as::<_, DocumentListRow>(
            r#"
            SELECT id, title, filename, file_size, created_at
            FROM documents
            ORDER BY created_at DESC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&state.pool)
        .await
        .map_err(|e| ApiError::Internal(format!("list failed: {e}")))?
    };

    Ok(Json(DocumentListResponse { items: rows }))
}

async fn download_document(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let row = sqlx::query_as::<_, DownloadRow>(
        r#"
        SELECT filename, mime_type, ciphertext, nonce
        FROM documents
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(format!("db error: {e}")))?
    .ok_or_else(|| ApiError::NotFound("document not found".to_owned()))?;

    let decrypted = decrypt_bytes(&state.encryption_key, &row.nonce, &row.ciphertext)?;
    let mut response = Response::new(Body::from(decrypted));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/pdf"));
    let safe_name = sanitize_filename(&row.filename);
    let disposition = format!("attachment; filename=\"{safe_name}\"");
    let disposition = HeaderValue::from_str(&disposition)
        .map_err(|e| ApiError::Internal(format!("invalid content disposition: {e}")))?;
    response
        .headers_mut()
        .insert(CONTENT_DISPOSITION, disposition);

    if let Ok(mime) = HeaderValue::from_str(&row.mime_type) {
        response.headers_mut().insert(CONTENT_TYPE, mime);
    }

    Ok(response)
}

async fn list_templates(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
) -> Result<Json<Vec<TemplateRow>>, ApiError> {
    let rows = sqlx::query_as::<_, TemplateRow>(
        r#"
        SELECT id, name, template_type, docx_filename, created_at, updated_at
        FROM templates
        ORDER BY updated_at DESC
        "#,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(format!("failed to fetch templates: {e}")))?;

    Ok(Json(rows))
}

async fn upsert_template(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    Json(req): Json<TemplateUpsertRequest>,
) -> Result<Json<TemplateRow>, ApiError> {
    let name = req.name.trim();
    let body = req.body.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("template name is required".to_owned()));
    }
    if body.is_empty() {
        return Err(ApiError::BadRequest("template body is required".to_owned()));
    }
    if body.len() > 200_000 {
        return Err(ApiError::BadRequest(
            "template body is too large (max 200000 chars)".to_owned(),
        ));
    }

    let row = sqlx::query_as::<_, TemplateRow>(
        r#"
        INSERT INTO templates (id, name, body, template_type, docx_ciphertext, docx_nonce, docx_filename)
        VALUES ($1, $2, $3, 'text', NULL, NULL, NULL)
        ON CONFLICT (name)
        DO UPDATE SET
            body = EXCLUDED.body,
            template_type = 'text',
            docx_ciphertext = NULL,
            docx_nonce = NULL,
            docx_filename = NULL,
            updated_at = NOW()
        RETURNING id, name, template_type, docx_filename, created_at, updated_at
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(name)
    .bind(body)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(format!("failed to save template: {e}")))?;

    Ok(Json(row))
}

async fn upload_docx_template(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    mut multipart: Multipart,
) -> Result<Json<TemplateRow>, ApiError> {
    let mut name: Option<String> = None;
    let mut file_name: Option<String> = None;
    let mut file_bytes: Option<Vec<u8>> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::BadRequest(format!("invalid multipart payload: {e}")))?
    {
        let field_name = field.name().unwrap_or_default().to_owned();
        if field_name == "name" {
            let text = field
                .text()
                .await
                .map_err(|e| ApiError::BadRequest(format!("invalid template name: {e}")))?;
            if !text.trim().is_empty() {
                name = Some(text.trim().to_owned());
            }
            continue;
        }
        if field_name == "file" {
            file_name = field.file_name().map(ToOwned::to_owned);
            let bytes = field
                .bytes()
                .await
                .map_err(|e| ApiError::BadRequest(format!("invalid file bytes: {e}")))?;
            file_bytes = Some(bytes.to_vec());
        }
    }

    let template_name = name.ok_or_else(|| ApiError::BadRequest("name is required".to_owned()))?;
    if template_name.len() > 200 {
        return Err(ApiError::BadRequest(
            "template name is too long (max 200 chars)".to_owned(),
        ));
    }
    let bytes =
        file_bytes.ok_or_else(|| ApiError::BadRequest("DOCX file is required".to_owned()))?;
    if bytes.len() > state.cfg.max_upload_bytes {
        return Err(ApiError::BadRequest(format!(
            "template file too large, max {} bytes",
            state.cfg.max_upload_bytes
        )));
    }
    validate_docx_template(&bytes)?;

    let filename = file_name
        .as_deref()
        .map(sanitize_filename)
        .unwrap_or_else(|| "template.docx".to_owned());
    let (nonce, ciphertext) = encrypt_bytes(&state.encryption_key, &bytes)?;

    let row = sqlx::query_as::<_, TemplateRow>(
        r#"
        INSERT INTO templates (
            id, name, body, template_type, docx_ciphertext, docx_nonce, docx_filename
        )
        VALUES ($1, $2, '', 'docx', $3, $4, $5)
        ON CONFLICT (name)
        DO UPDATE SET
            body = '',
            template_type = 'docx',
            docx_ciphertext = EXCLUDED.docx_ciphertext,
            docx_nonce = EXCLUDED.docx_nonce,
            docx_filename = EXCLUDED.docx_filename,
            updated_at = NOW()
        RETURNING id, name, template_type, docx_filename, created_at, updated_at
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(template_name)
    .bind(ciphertext)
    .bind(nonce)
    .bind(filename)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(format!("failed to save DOCX template: {e}")))?;

    Ok(Json(row))
}

async fn render_template(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(template_id): Path<Uuid>,
    Json(req): Json<TemplateRenderRequest>,
) -> Result<Response, ApiError> {
    let template = sqlx::query_as::<_, TemplateSourceRow>(
        r#"
        SELECT name, body, template_type, docx_ciphertext, docx_nonce
        FROM templates
        WHERE id = $1
        "#,
    )
    .bind(template_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(format!("db error: {e}")))?
    .ok_or_else(|| ApiError::NotFound("template not found".to_owned()))?;

    let output_format = parse_output_format(req.output_format.as_deref())?;
    let (output_bytes, output_mime, output_ext, index_text) = if template.template_type == "docx" {
        let encrypted = template.docx_ciphertext.as_deref().ok_or_else(|| {
            ApiError::Internal("DOCX template storage is corrupted: ciphertext missing".to_owned())
        })?;
        let nonce = template.docx_nonce.as_deref().ok_or_else(|| {
            ApiError::Internal("DOCX template storage is corrupted: nonce missing".to_owned())
        })?;
        let source_docx = decrypt_bytes(&state.encryption_key, nonce, encrypted)?;
        let rendered_docx = render_docx_template(&source_docx, &req.values, &state.handlebars)?;
        let index_text = extract_docx_index_text(&rendered_docx)
            .unwrap_or_else(|_| values_to_index_text(&req.values))
            .chars()
            .take(400_000)
            .collect::<String>();

        match output_format {
            OutputFormat::Pdf => {
                let pdf = convert_docx_to_pdf(&rendered_docx, &state.cfg.libreoffice_bin).await?;
                (
                    pdf,
                    "application/pdf",
                    "pdf",
                    normalize_text_for_index(&index_text),
                )
            }
            OutputFormat::Docx => (
                rendered_docx,
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "docx",
                normalize_text_for_index(&index_text),
            ),
        }
    } else {
        let rendered = state
            .handlebars
            .render_template(&template.body, &req.values)
            .map_err(|e| ApiError::BadRequest(format!("template render failed: {e}")))?;
        match output_format {
            OutputFormat::Pdf => {
                let pdf = render_plain_text_pdf(&rendered, &state.cfg)?;
                (
                    pdf,
                    "application/pdf",
                    "pdf",
                    normalize_text_for_index(&rendered),
                )
            }
            OutputFormat::Docx => {
                return Err(ApiError::BadRequest(
                    "DOCX output is available only for DOCX templates".to_owned(),
                ));
            }
        }
    };

    let safe_title = req
        .title
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or(template.name.as_str());
    let filename = format!("{}.{}", sanitize_filename(safe_title), output_ext);
    let mut maybe_document_id: Option<Uuid> = None;

    if req.save_as_document.unwrap_or(false) {
        let checksum = sha256(&output_bytes);
        let (nonce, ciphertext) = encrypt_bytes(&state.encryption_key, &output_bytes)?;
        let doc_id = Uuid::new_v4();

        sqlx::query(
            r#"
            INSERT INTO documents (
                id, title, filename, mime_type, file_size,
                ciphertext, nonce, checksum, extracted_text, uploaded_by
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(doc_id)
        .bind(safe_title)
        .bind(&filename)
        .bind(output_mime)
        .bind(output_bytes.len() as i64)
        .bind(ciphertext)
        .bind(nonce)
        .bind(checksum)
        .bind(index_text.clone())
        .bind(user.username)
        .execute(&state.pool)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to store rendered doc: {e}")))?;

        maybe_document_id = Some(doc_id);
    }

    let mut response = Response::new(Body::from(output_bytes));
    let content_type = HeaderValue::from_str(output_mime)
        .map_err(|e| ApiError::Internal(format!("invalid content type: {e}")))?;
    response.headers_mut().insert(CONTENT_TYPE, content_type);
    let disposition = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
        .map_err(|e| ApiError::Internal(format!("invalid content disposition: {e}")))?;
    response
        .headers_mut()
        .insert(CONTENT_DISPOSITION, disposition);
    if let Some(document_id) = maybe_document_id {
        let header = HeaderValue::from_str(&document_id.to_string())
            .map_err(|e| ApiError::Internal(format!("invalid header value: {e}")))?;
        response.headers_mut().insert("x-document-id", header);
    }

    Ok(response)
}

async fn delete_document(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<Json<DeleteResult>, ApiError> {
    let result = sqlx::query("DELETE FROM documents WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to delete document: {e}")))?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("document not found".to_owned()));
    }
    Ok(Json(DeleteResult { deleted: true }))
}

async fn delete_template(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<Json<DeleteResult>, ApiError> {
    let result = sqlx::query("DELETE FROM templates WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to delete template: {e}")))?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("template not found".to_owned()));
    }
    Ok(Json(DeleteResult { deleted: true }))
}

#[derive(Clone, Copy, Debug)]
enum OutputFormat {
    Pdf,
    Docx,
}

fn parse_output_format(value: Option<&str>) -> Result<OutputFormat, ApiError> {
    match value.unwrap_or("pdf").trim().to_ascii_lowercase().as_str() {
        "pdf" => Ok(OutputFormat::Pdf),
        "docx" => Ok(OutputFormat::Docx),
        _ => Err(ApiError::BadRequest(
            "output_format must be either 'pdf' or 'docx'".to_owned(),
        )),
    }
}

fn validate_docx_template(bytes: &[u8]) -> Result<(), ApiError> {
    if bytes.len() < 4 || !bytes.starts_with(b"PK") {
        return Err(ApiError::BadRequest(
            "invalid DOCX: file is not a ZIP container".to_owned(),
        ));
    }

    let cursor = Cursor::new(bytes);
    let mut archive = ZipArchive::new(cursor)
        .map_err(|e| ApiError::BadRequest(format!("invalid DOCX archive: {e}")))?;
    let mut has_content_types = false;
    let mut has_document_xml = false;
    let mut total_uncompressed = 0_u64;

    for i in 0..archive.len() {
        let file = archive
            .by_index(i)
            .map_err(|e| ApiError::BadRequest(format!("invalid DOCX archive entry: {e}")))?;
        let name = file.name();
        if is_unsafe_archive_path(name) {
            return Err(ApiError::BadRequest(
                "invalid DOCX: unsafe archive path".to_owned(),
            ));
        }
        if name == "[Content_Types].xml" {
            has_content_types = true;
        }
        if name == "word/document.xml" {
            has_document_xml = true;
        }
        total_uncompressed = total_uncompressed.saturating_add(file.size());
        if total_uncompressed > 50 * 1024 * 1024 {
            return Err(ApiError::BadRequest(
                "invalid DOCX: uncompressed size is too large".to_owned(),
            ));
        }
    }

    if !has_content_types || !has_document_xml {
        return Err(ApiError::BadRequest(
            "invalid DOCX: required DOCX entries are missing".to_owned(),
        ));
    }

    Ok(())
}

fn is_unsafe_archive_path(path: &str) -> bool {
    path.starts_with('/')
        || path.starts_with('\\')
        || path.contains("..")
        || path.contains(':')
        || path.is_empty()
}

fn render_docx_template(
    template_docx: &[u8],
    values: &Value,
    hb: &Handlebars<'_>,
) -> Result<Vec<u8>, ApiError> {
    let reader = Cursor::new(template_docx);
    let mut archive = ZipArchive::new(reader)
        .map_err(|e| ApiError::BadRequest(format!("invalid DOCX archive: {e}")))?;
    let mut writer = ZipWriter::new(Cursor::new(Vec::<u8>::new()));
    let options = FileOptions::default().compression_method(CompressionMethod::Deflated);

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| ApiError::Internal(format!("failed to read DOCX entry: {e}")))?;
        let name = entry.name().to_owned();
        if is_unsafe_archive_path(&name) {
            return Err(ApiError::BadRequest(
                "invalid DOCX template: unsafe archive path".to_owned(),
            ));
        }

        if entry.is_dir() || name.ends_with('/') {
            writer
                .add_directory(name, options)
                .map_err(|e| ApiError::Internal(format!("failed to write DOCX directory: {e}")))?;
            continue;
        }

        let mut data = Vec::new();
        entry
            .read_to_end(&mut data)
            .map_err(|e| ApiError::Internal(format!("failed to read DOCX data: {e}")))?;

        let out_data = if is_docx_xml_template_target(&name) {
            let xml = String::from_utf8(data).map_err(|e| {
                ApiError::Internal(format!("DOCX XML contains invalid utf-8 at {name}: {e}"))
            })?;
            hb.render_template(&xml, values)
                .map_err(|e| ApiError::BadRequest(format!("template render failed: {e}")))?
                .into_bytes()
        } else {
            data
        };

        writer
            .start_file(name, options)
            .map_err(|e| ApiError::Internal(format!("failed to start DOCX file: {e}")))?;
        writer
            .write_all(&out_data)
            .map_err(|e| ApiError::Internal(format!("failed to write DOCX file: {e}")))?;
    }

    let cursor = writer
        .finish()
        .map_err(|e| ApiError::Internal(format!("failed to finalize DOCX archive: {e}")))?;
    Ok(cursor.into_inner())
}

fn is_docx_xml_template_target(name: &str) -> bool {
    name.starts_with("word/") && name.ends_with(".xml")
}

async fn convert_docx_to_pdf(docx: &[u8], libreoffice_bin: &str) -> Result<Vec<u8>, ApiError> {
    let docx = docx.to_vec();
    let libreoffice_bin = libreoffice_bin.to_owned();
    task::spawn_blocking(move || -> Result<Vec<u8>, ApiError> {
        let dir = tempdir().map_err(|e| ApiError::Internal(format!("temp dir failed: {e}")))?;
        let docx_path = dir.path().join("rendered.docx");
        std::fs::write(&docx_path, &docx)
            .map_err(|e| ApiError::Internal(format!("failed to write DOCX temp file: {e}")))?;

        let output = StdCommand::new(&libreoffice_bin)
            .arg("--headless")
            .arg("--nologo")
            .arg("--nofirststartwizard")
            .arg("--convert-to")
            .arg("pdf:writer_pdf_Export")
            .arg("--outdir")
            .arg(dir.path())
            .arg(&docx_path)
            .output()
            .map_err(|e| {
                ApiError::Internal(format!(
                    "failed to run libreoffice ({libreoffice_bin}): {e}"
                ))
            })?;

        if !output.status.success() {
            return Err(ApiError::Internal(format!(
                "libreoffice conversion failed with status {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let pdf_path = dir.path().join("rendered.pdf");
        std::fs::read(&pdf_path)
            .map_err(|e| ApiError::Internal(format!("failed to read converted PDF: {e}")))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("docx->pdf task join error: {e}")))?
}

fn extract_docx_index_text(docx: &[u8]) -> Result<String, ApiError> {
    let mut archive = ZipArchive::new(Cursor::new(docx))
        .map_err(|e| ApiError::BadRequest(format!("invalid DOCX archive: {e}")))?;
    let mut out = String::new();
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| ApiError::Internal(format!("failed to read DOCX entry: {e}")))?;
        let name = entry.name().to_owned();
        if !is_docx_xml_template_target(&name) {
            continue;
        }
        let mut data = Vec::new();
        entry
            .read_to_end(&mut data)
            .map_err(|e| ApiError::Internal(format!("failed to read DOCX XML entry: {e}")))?;
        if let Ok(xml) = String::from_utf8(data) {
            let text = extract_word_text_nodes(&xml);
            if !text.is_empty() {
                if !out.is_empty() {
                    out.push('\n');
                }
                out.push_str(&text);
            }
        }
    }
    Ok(out)
}

fn extract_word_text_nodes(xml: &str) -> String {
    let mut out = String::new();
    let mut cursor = 0_usize;
    while let Some(start_rel) = xml[cursor..].find("<w:t") {
        let start = cursor + start_rel;
        let Some(tag_end_rel) = xml[start..].find('>') else {
            break;
        };
        let content_start = start + tag_end_rel + 1;
        let Some(close_rel) = xml[content_start..].find("</w:t>") else {
            break;
        };
        let content_end = content_start + close_rel;
        let text = decode_xml_entities(&xml[content_start..content_end]);
        if !text.trim().is_empty() {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(text.trim());
        }
        cursor = content_end + "</w:t>".len();
    }
    out
}

fn decode_xml_entities(input: &str) -> String {
    input
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

fn values_to_index_text(values: &Value) -> String {
    serde_json::to_string(values).unwrap_or_default()
}

fn required_env(key: &str) -> Result<String, ApiError> {
    std::env::var(key).map_err(|_| ApiError::Internal(format!("{key} is required")))
}

fn load_encryption_key() -> Result<[u8; 32], ApiError> {
    let raw = required_env("DOCS_ENCRYPTION_KEY")?;
    let decoded = BASE64
        .decode(raw.as_bytes())
        .map_err(|e| ApiError::Internal(format!("DOCS_ENCRYPTION_KEY must be base64: {e}")))?;
    if decoded.len() != 32 {
        return Err(ApiError::Internal(
            "DOCS_ENCRYPTION_KEY must decode to exactly 32 bytes".to_owned(),
        ));
    }
    let mut key = [0_u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

fn encrypt_bytes(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ApiError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| ApiError::Internal(format!("failed to init cipher: {e}")))?;
    let mut nonce = [0_u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(aes_gcm::Nonce::from_slice(&nonce), plaintext)
        .map_err(|e| ApiError::Internal(format!("encryption failed: {e}")))?;
    Ok((nonce.to_vec(), ciphertext))
}

fn decrypt_bytes(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ApiError> {
    if nonce.len() != 12 {
        return Err(ApiError::Internal("invalid nonce length".to_owned()));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| ApiError::Internal(format!("failed to init cipher: {e}")))?;
    cipher
        .decrypt(aes_gcm::Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| ApiError::Internal(format!("decryption failed: {e}")))
}

fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn is_pdf(file: &[u8]) -> bool {
    file.starts_with(b"%PDF-")
}

fn try_extract_pdf_text(file: &[u8]) -> Result<String, ApiError> {
    pdf_extract::extract_text_from_mem(file)
        .map_err(|e| ApiError::BadRequest(format!("failed to parse PDF text: {e}")))
}

async fn run_ocr(file: &[u8], lang: &str) -> Result<String, ApiError> {
    let file = file.to_vec();
    let lang = lang.to_owned();
    let result = task::spawn_blocking(move || -> Result<String, ApiError> {
        let dir = tempdir().map_err(|e| ApiError::Internal(format!("temp dir failed: {e}")))?;
        let pdf_path = dir.path().join("scan.pdf");
        std::fs::write(&pdf_path, &file)
            .map_err(|e| ApiError::Internal(format!("failed to write temp PDF: {e}")))?;

        let prefix = dir.path().join("page");
        let pdftoppm_status = StdCommand::new("pdftoppm")
            .arg("-png")
            .arg(&pdf_path)
            .arg(&prefix)
            .status()
            .map_err(|e| ApiError::Internal(format!("failed to run pdftoppm: {e}")))?;

        if !pdftoppm_status.success() {
            warn!("pdftoppm finished with non-zero status");
            return Ok(String::new());
        }

        let mut pages = std::fs::read_dir(dir.path())
            .map_err(|e| ApiError::Internal(format!("failed to list OCR files: {e}")))?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|v| v.to_str())
                    .map(|name| name.starts_with("page-") && name.ends_with(".png"))
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();

        pages.sort();
        let mut full_text = String::new();

        for page in pages {
            let output = StdCommand::new("tesseract")
                .arg(&page)
                .arg("stdout")
                .arg("-l")
                .arg(&lang)
                .output()
                .map_err(|e| ApiError::Internal(format!("failed to run tesseract: {e}")))?;

            if output.status.success() {
                full_text.push_str(&String::from_utf8_lossy(&output.stdout));
                full_text.push('\n');
            } else {
                warn!("tesseract failed for {}", page.display());
            }
        }

        Ok(full_text)
    })
    .await
    .map_err(|e| ApiError::Internal(format!("OCR task join error: {e}")))??;

    Ok(result)
}

fn normalize_text_for_index(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(400_000)
        .collect()
}

fn clean_search_query(input: String) -> Option<String> {
    let q = input.trim().to_owned();
    if q.is_empty() {
        None
    } else {
        Some(q.chars().take(200).collect())
    }
}

fn sanitize_filename(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "document.pdf".to_owned()
    } else {
        out
    }
}

fn render_plain_text_pdf(rendered: &str, cfg: &AppConfig) -> Result<Vec<u8>, ApiError> {
    let (doc, page1, layer1) = PdfDocument::new("template", Mm(210.0), Mm(297.0), "Layer 1");
    let font = match File::open(&cfg.pdf_font_path) {
        Ok(file) => doc
            .add_external_font(file)
            .map_err(|e| ApiError::Internal(format!("failed to load PDF font: {e}")))?,
        Err(primary_err) => {
            warn!(
                "primary PDF font is unavailable at {}: {}; trying fallback {}",
                cfg.pdf_font_path, primary_err, cfg.pdf_font_fallback_path
            );
            let fallback = File::open(&cfg.pdf_font_fallback_path).map_err(|fallback_err| {
                ApiError::Internal(format!(
                    "cannot open PDF fonts. primary {} ({primary_err}), fallback {} ({fallback_err})",
                    cfg.pdf_font_path, cfg.pdf_font_fallback_path
                ))
            })?;
            doc.add_external_font(fallback)
                .map_err(|e| ApiError::Internal(format!("failed to load fallback font: {e}")))?
        }
    };

    let mut current_layer = doc.get_page(page1).get_layer(layer1);
    let mut y = 282.0_f32;
    let font_size = cfg.pdf_font_size_pt;
    let line_height = (font_size * 1.45).max(6.0);
    let max_chars = 100;

    for paragraph in rendered.lines() {
        let wrapped = wrap_line(paragraph, max_chars);
        if wrapped.is_empty() {
            if y < 20.0 {
                let (p, l) = doc.add_page(Mm(210.0), Mm(297.0), "Layer");
                current_layer = doc.get_page(p).get_layer(l);
                y = 282.0;
            }
            y -= line_height;
            continue;
        }

        for line in wrapped {
            if y < 20.0 {
                let (p, l) = doc.add_page(Mm(210.0), Mm(297.0), "Layer");
                current_layer = doc.get_page(p).get_layer(l);
                y = 282.0;
            }
            current_layer.use_text(line, font_size, Mm(15.0), Mm(y), &font);
            y -= line_height;
        }
    }

    let mut bytes = Vec::new();
    doc.save(&mut BufWriter::new(&mut bytes))
        .map_err(|e| ApiError::Internal(format!("failed to save PDF: {e}")))?;
    Ok(bytes)
}

fn wrap_line(input: &str, max_chars: usize) -> Vec<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut result = Vec::new();
    let mut line = String::new();
    let mut line_chars = 0_usize;
    for word in trimmed.split_whitespace() {
        let word_chars = word.chars().count();
        if line.is_empty() {
            line.push_str(word);
            line_chars = word_chars;
            continue;
        }
        if line_chars + 1 + word_chars > max_chars {
            result.push(line);
            line = word.to_owned();
            line_chars = word_chars;
        } else {
            line.push(' ');
            line.push_str(word);
            line_chars += 1 + word_chars;
        }
    }
    if !line.is_empty() {
        result.push(line);
    }
    result
}
