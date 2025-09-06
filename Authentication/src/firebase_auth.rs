use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::collections::HashMap;
use thiserror::Error;
use log::error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Invalid token format")]
    InvalidToken,
    #[error("Token verification failed: {0}")]
    VerificationFailed(String),
    #[error("Network error: {0}")]
    NetworkError(String),
}

#[derive(Debug, Deserialize)]
pub struct FirebaseClaims {
    pub email: String,
    pub exp: usize,
    pub aud: String,  // Audience
    pub iss: String,  // Issuer
    pub sub: String,  // Subject (user ID)
}

pub async fn verify_firebase_token(token: &str, project_id: &str) -> Result<FirebaseClaims, AuthError> {
    if token.is_empty() || token.len() > 2048 {
        return Err(AuthError::InvalidToken);
    }

    let jwks_url = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";
    
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| AuthError::NetworkError(e.to_string()))?;
    
    let resp = client.get(jwks_url)
        .send()
        .await
        .map_err(|e| AuthError::NetworkError(e.to_string()))?;
    
    let certs: HashMap<String, String> = resp.json()
        .await
        .map_err(|e| AuthError::NetworkError(e.to_string()))?;

    let header = decode_header(token)
        .map_err(|e| AuthError::VerificationFailed(e.to_string()))?;
    
    let kid = header.kid
        .ok_or(AuthError::VerificationFailed("Missing kid in token header".to_string()))?;

    let cert_pem = certs.get(&kid)
        .ok_or(AuthError::VerificationFailed("Key not found".to_string()))?;
    
    let decoding_key = DecodingKey::from_rsa_pem(cert_pem.as_bytes())
        .map_err(|e| AuthError::VerificationFailed(e.to_string()))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[project_id]);
    validation.set_issuer(&[&format!("https://securetoken.google.com/{}", project_id)]);
    
    let data = decode::<FirebaseClaims>(token, &decoding_key, &validation)
        .map_err(|e| {
            error!("Token validation failed: {}", e);
            AuthError::VerificationFailed(e.to_string())
        })?;

    Ok(data.claims)
}
