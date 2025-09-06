mod firebase_auth;

use actix_web::{get, middleware::Logger, web, App, HttpRequest, HttpResponse, HttpServer, Responder, Result};
use sqlx::{MySqlPool, Row};
use dotenv::dotenv;
use log::{info, error, warn};
use serde_json::json;

#[derive(serde::Deserialize, Clone)]
struct Config {
    database_url: String,
    firebase_project_id: String,
    server_host: String,
    server_port: u16,
}

impl Config {
    fn from_env() -> anyhow::Result<Self> {
        Ok(Config {
            database_url: std::env::var("DATABASE_URL")?,
            firebase_project_id: std::env::var("FIREBASE_PROJECT_ID")?,
            server_host: std::env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            server_port: std::env::var("SERVER_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()?,
        })
    }
}

#[get("/profile")]
async fn profile(req: HttpRequest, pool: web::Data<MySqlPool>, config: web::Data<Config>) -> Result<HttpResponse> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    let token = match auth_header {
        Some(header) if header.starts_with("Bearer ") => &header[7..],
        _ => {
            warn!("Missing or invalid Authorization header");
            return Ok(HttpResponse::Unauthorized().json(json!({
                "error": "Missing or invalid Authorization header"
            })));
        }
    };

    let claims = match firebase_auth::verify_firebase_token(token, &config.firebase_project_id).await {
        Ok(claims) => claims,
        Err(e) => {
            warn!("Token verification failed: {}", e);
            return Ok(HttpResponse::Unauthorized().json(json!({
                "error": "Invalid or expired token"
            })));
        }
    };

    if claims.email.is_empty() || !claims.email.contains('@') {
        warn!("Invalid email in token: {}", claims.email);
        return Ok(HttpResponse::BadRequest().json(json!({
            "error": "Invalid email format"
        })));
    }

    match sqlx::query("SELECT email FROM users WHERE email = ? LIMIT 1")
        .bind(&claims.email)
        .fetch_optional(pool.get_ref())
        .await
    {
        Ok(Some(_)) => {
            info!("Successful authentication for user: {}", claims.email);
            Ok(HttpResponse::Ok().json(json!({
                "status": "success",
                "email": claims.email,
                "user_id": claims.sub
            })))
        }
        Ok(None) => {
            warn!("Email not found in database: {}", claims.email);
            Ok(HttpResponse::Forbidden().json(json!({
                "error": "Access denied"
            })))
        }
        Err(e) => {
            error!("Database error: {}", e);
            Ok(HttpResponse::InternalServerError().json(json!({
                "error": "Internal server error"
            })))
        }
    }
}

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();
    env_logger::init();

    let config = Config::from_env()?;
    
    let pool = MySqlPool::connect(&config.database_url)
        .await
        .map_err(|e| anyhow::anyhow!("Database connection failed: {}", e))?;

    info!("🚀 Server starting on {}:{}", config.server_host, config.server_port);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(config.clone()))
            .wrap(Logger::default())
            .service(profile)
    })
    .bind((config.server_host.clone(), config.server_port))?
    .run()
    .await
    .map_err(|e| anyhow::anyhow!("Server error: {}", e))
}
