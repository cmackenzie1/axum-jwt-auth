# axum-jwt-auth

[![Rust](https://github.com/cmackenzie1/axum-jwt-auth/actions/workflows/rust.yml/badge.svg)](https://github.com/cmackenzie1/axum-jwt-auth/actions/workflows/rust.yml)
[![Crates.io Version](https://img.shields.io/crates/v/axum-jwt-auth)](https://crates.io/crates/axum-jwt-auth)
[![docs.rs](https://img.shields.io/docsrs/axum-jwt-auth)](https://docs.rs/axum-jwt-auth)

A Rust library providing JWT authentication middleware for Axum web applications. It supports both local and remote JWKS validation, handles token extraction and validation, and provides strongly-typed claims access in your request handlers. Built on top of jsonwebtoken, it offers a simple yet flexible API for securing your Axum routes with JWT authentication.

See [examples](./examples/) for how to use.

# Usage

```rust
use axum::{
    extract::FromRef,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};

use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use axum_jwt_auth::{Claims, Decoder, JwtDecoderState, LocalDecoder};
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

// Claims extractor will return a 401 if the token is invalid
async fn user_info(Claims(claims): Claims<MyClaims>) -> Response {
    Json(claims).into_response()
}

async fn login() -> Response {
    let key = EncodingKey::from_rsa_pem(include_bytes!("../jwt.key")).unwrap();
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
    // Set the audience to the expected value. Not setting this will cause the token to be invalid.
    validation.set_audience(&["https://example.com"]);
    let decoder: Decoder = LocalDecoder::new(keys, validation).into();
    let state = AppState {
        decoder: JwtDecoderState { decoder },
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/user_info", get(user_info))
        .route("/login", post(login))
        .with_state(state);

    // run it on localhost:3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```
