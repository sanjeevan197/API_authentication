use actix_web::{post, web, HttpResponse, Responder};
use sqlx::MySqlPool;
use serde::Deserialize;
use crate::services::jwt::generate_token;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[post("/login")]
pub async fn login(body: web::Json<LoginRequest>, pool: web::Data<MySqlPool>) -> impl Responder {
    let user = sqlx::query!(
        "SELECT email, password FROM users WHERE email = ?",
        body.email
    )
    .fetch_optional(pool.get_ref())
    .await
    .unwrap();

    if let Some(record) = user {
        if record.password == body.password {
            let token = generate_token(&record.email);
            return HttpResponse::Ok().json(serde_json::json!({
                "status": "success",
                "token": token
            }));
        }
    }

    HttpResponse::Unauthorized().json(serde_json::json!({
        "status": "error",
        "message": "Invalid email or password"
    }))
}
