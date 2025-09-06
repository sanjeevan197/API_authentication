use actix_web::{get, web, HttpRequest, HttpResponse, Responder};
use sqlx::MySqlPool;
use crate::services::jwt::verify_token;

#[get("/profile")]
pub async fn profile(req: HttpRequest, pool: web::Data<MySqlPool>) -> impl Responder {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    if auth_header.is_none() || !auth_header.unwrap().starts_with("Bearer ") {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Missing or invalid token"
        }));
    }

    let token = &auth_header.unwrap()[7..];
    let claims = verify_token(token);

    if claims.is_none() {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Invalid or expired token"
        }));
    }

    let email = claims.unwrap().sub;

    let user = sqlx::query!("SELECT email FROM users WHERE email = ?", email)
        .fetch_optional(pool.get_ref())
        .await
        .unwrap();

    if user.is_some() {
        HttpResponse::Ok().json(serde_json::json!({
            "status": "success",
            "email": email
        }))
    } else {
        HttpResponse::Unauthorized().json(serde_json::json!({
            "status": "error",
            "message": "User not found"
        }))
    }
}
