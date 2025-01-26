use std::sync::Arc;

use axum::{
    extract::FromRef,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};

use axum_jwt_auth::{Claims, Decoder, JwtDecoderState, LocalDecoder};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Clone, FromRef)]
struct AppState {
    decoder: JwtDecoderState<MyClaims>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MyClaims {
    iat: u64,
    aud: String,
    exp: u64,
}

#[tokio::test]
async fn token_is_valid() {
    // Load the keys
    let encoding_key = EncodingKey::from_rsa_pem(include_bytes!("jwt.key")).unwrap();
    let decoding_key = DecodingKey::from_rsa_pem(include_bytes!("jwt.key.pub")).unwrap();

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&["https://example.com"]);
    let decoder: Decoder<MyClaims> =
        Arc::new(LocalDecoder::new(vec![decoding_key.to_owned()], validation));
    let state = AppState {
        decoder: JwtDecoderState { decoder },
    };

    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route(
            "/user_info",
            get(|Claims(claims): Claims<MyClaims>| async { Json(claims) }),
        )
        .route(
            "/login",
            post(|| async move {
                let mut header = Header::new(Algorithm::RS256);
                header.kid = Some("test".to_string());

                let exp = Utc::now() + Duration::hours(1);
                let claims = MyClaims {
                    iat: 1234567890,
                    aud: "https://example.com".to_string(),
                    exp: exp.timestamp() as u64,
                };

                let token = encode::<MyClaims>(&header, &claims, &encoding_key).unwrap();

                token.into_response()
            }),
        )
        .with_state(state);

    // run it on localhost:3000
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
        axum::serve(listener, app).await.unwrap();
    });

    // Test the server
    let client = reqwest::Client::new();

    // Unauthorized
    let res = client
        .get("http://localhost:3000/user_info")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);

    // Login
    let res = client
        .post("http://localhost:3000/login")
        .send()
        .await
        .unwrap();
    let token = res.text().await.unwrap();

    // Authorized with token
    let res = client
        .get("http://localhost:3000/user_info")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body = res.text().await.unwrap();
    let claims: MyClaims = serde_json::from_str(&body).unwrap();
    assert_eq!(claims.aud, "https://example.com");
    assert_eq!(claims.iat, 1234567890);
    assert!(claims.exp > Utc::now().timestamp() as u64);
}
