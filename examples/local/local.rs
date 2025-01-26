use std::sync::Arc;

use axum::{
    extract::{FromRef, State},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use axum_jwt_auth::{Claims, JwtDecoderState, LocalDecoder};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MyClaims {
    iat: u64,
    aud: String,
    exp: u64,
}

#[derive(Clone, FromRef)]
struct AppState {
    decoder: JwtDecoderState<MyClaims>,
}

async fn index() -> Response {
    "Hello, World!".into_response()
}

#[axum::debug_handler]
async fn user_info(Claims(claims): Claims<MyClaims>, State(_state): State<AppState>) -> Response {
    Json(claims).into_response()
}

async fn login() -> Response {
    let key = EncodingKey::from_rsa_pem(include_bytes!("jwt.key")).unwrap();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test".to_string());

    let exp = Utc::now() + Duration::hours(1);
    let claims = MyClaims {
        iat: 1234567890,
        aud: "https://example.com".to_string(),
        exp: exp.timestamp() as u64,
    };

    let token = encode::<MyClaims>(&header, &claims, &key).unwrap();

    token.into_response()
}

#[tokio::main]
async fn main() {
    let keys = vec![DecodingKey::from_rsa_pem(include_bytes!("jwt.key.pub")).unwrap()];
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&["https://example.com"]);
    let decoder = LocalDecoder::new(keys, validation);
    let state = AppState {
        decoder: JwtDecoderState {
            decoder: Arc::new(decoder),
        },
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/user_info", get(user_info))
        .route("/login", post(login))
        .with_state(state);

    // Create client and server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("Failed to bind");
    let client = reqwest::Client::new();

    // Run server in background
    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Make requests to test endpoints
    let login_resp = client
        .post("http://127.0.0.1:3000/login")
        .send()
        .await
        .expect("Login failed");
    let token = login_resp.text().await.expect("Failed to get token");

    let user_info = client
        .get("http://127.0.0.1:3000/user_info")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .expect("User info request failed")
        .json::<MyClaims>()
        .await
        .expect("Failed to parse claims");

    println!("Successfully validated claims: {:?}", user_info);

    // Clean shutdown
    server_handle.abort();
}
