use axum::{
    extract::FromRef,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};

use axum_jwt_auth::{Claims, Decoder, JwtDecoderState, LocalDecoder};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Clone, FromRef)]
struct AppState {
    decoder: JwtDecoderState,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MyClaims {
    iat: u64,
    aud: String,
    exp: u64,
}

async fn index() -> Response {
    "Hello, World!".into_response()
}

async fn user_info(Claims(claims): Claims<MyClaims>) -> Response {
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
    let validation = Validation::new(Algorithm::RS256);
    let decoder: Decoder = LocalDecoder::new(keys, validation).into();
    let state = AppState {
        decoder: JwtDecoderState { decoder },
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/user_info", get(user_info))
        .route("/login", post(login))
        .with_state(state);

    // run it with hyper on localhost:3000
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
