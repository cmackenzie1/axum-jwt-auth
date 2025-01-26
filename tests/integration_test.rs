use std::sync::Arc;

use axum::{
    extract::FromRef,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};

use axum_jwt_auth::{
    Claims, Decoder, JwtDecoder, JwtDecoderState, LocalDecoder, RemoteJwksDecoderBuilder,
    RemoteJwksDecoderConfigBuilder,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Clone, FromRef)]
struct AppState {
    decoder: JwtDecoderState<CustomClaims>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CustomClaims {
    iat: u64,
    aud: String,
    exp: u64,
}

#[tokio::test]
async fn local_decoder() {
    // Load the keys
    let encoding_key = EncodingKey::from_rsa_pem(include_bytes!("jwt.key")).unwrap();
    let decoding_key = DecodingKey::from_rsa_pem(include_bytes!("jwt.key.pub")).unwrap();

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&["https://example.com"]);
    let decoder: Decoder<CustomClaims> =
        Arc::new(LocalDecoder::new(vec![decoding_key.to_owned()], validation));
    let state = AppState {
        decoder: JwtDecoderState { decoder },
    };

    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route(
            "/user_info",
            get(|Claims(claims): Claims<CustomClaims>| async { Json(claims) }),
        )
        .route(
            "/login",
            post(|| async move {
                let mut header = Header::new(Algorithm::RS256);
                header.kid = Some("test".to_string());

                let exp = Utc::now() + Duration::hours(1);
                let claims = CustomClaims {
                    iat: 1234567890,
                    aud: "https://example.com".to_string(),
                    exp: exp.timestamp() as u64,
                };

                let token = encode::<CustomClaims>(&header, &claims, &encoding_key).unwrap();

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
    let claims: CustomClaims = serde_json::from_str(&body).unwrap();
    assert_eq!(claims.aud, "https://example.com");
    assert_eq!(claims.iat, 1234567890);
    assert!(claims.exp > Utc::now().timestamp() as u64);
}

#[tokio::test]
async fn remote_decoder() {
    // Initialize tracing for logging
    tracing_subscriber::fmt::init();

    // Create a test JWKS handler that returns a static JWKS
    let app = Router::new().route(
        "/.well-known/jwks.json",
        get(|| async { Json(json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": "1dea0016-46b8-4289-ad7b-226cfaf5305e",
                "n": "sPWeaqsN-2KZu9rlto59XASssMoaVjIxMYXtLyifky1sXS4EvYFnvr37X63B-lMwuZ3xACc7xsUPK-GXPe6XqZGJdj-Wgf7a3J6FieSNpnrDK4x6CMr0iAPgIhoEYp7BUyPKzPv21vMl6A5kJvlAAdxfPm3jhk5NDWHSfiFnWiC7UESARgyFl0TlJ-f9H3qaArkzp3Cb-m-wlHpleewOSr9maTPLdIS-ZzZ1ZC4lDIQnetJJ0kue-o1wAL4VmdBMY8IVxEutPAaZO-9G8eYJywZiDDkcrrqWymDvSUarcB_AOzEQjxN6nSSNuW6UbalfnDlGmR0kFK8fopraA4nwU4tG6fAuKTPpOmahC910IRAkedOp6IrRU-2LmcBQ0oyzukHjXd9o9_5MES2wTDFgZBalVRZCo55vdQt5CtQDQWVUbQ1y95dm_0EmmgZzWBgiguSKcO2QuqwYIiq5t9uikFleeVQDVnd-V6yZ5wWfnA6H0-dPw4VTEUkxaTN8jQImQtB9gvj8iknsGX08LGF5WjWh1ewJI0L74Ey5T_ytsXME6Xpn1qfXB2sr5tPol3KeV8pjuGrAymvaLJZz4ZqNY3f4wULfCsyVasUOdknMm8UmTgPR-vnDlF-1ItsmN-Jl-RJ1dFkXRDcelCIJS44sMSchnxv47OwnqvBHCPbiUI8",
                "e": "AQAB"
              }]
        })) }),
    );

    // Spawn the JWKS server
    let server_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:3001")
            .await
            .expect("Failed to bind JWKS server");
        axum::serve(listener, app).await.unwrap();
    });

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&["https://example.com"]);
    // Create remote decoder with test-appropriate config
    let decoder = RemoteJwksDecoderBuilder::default()
        .jwks_url("http://127.0.0.1:3001/.well-known/jwks.json".to_string())
        .config(
            RemoteJwksDecoderConfigBuilder::default()
                .cache_duration(Duration::milliseconds(100).to_std().unwrap()) // Short duration for testing
                .retry_count(1) // Minimal retries for faster tests
                .backoff(Duration::milliseconds(50).to_std().unwrap()) // Short backoff for testing
                .build()
                .unwrap(),
        )
        .validation(validation)
        .build()
        .expect("Failed to build decoder");

    // Start key refresh task
    let decoder_clone = decoder.clone();
    let refresh_handle = tokio::spawn(async move {
        decoder_clone.refresh_keys_periodically().await;
    });

    // Wait for initial key fetch
    tokio::time::sleep(Duration::seconds(1).to_std().unwrap()).await;

    // Test decoding with valid token
    let claims = CustomClaims {
        iat: 1234567890,
        aud: "https://example.com".to_string(),
        exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as u64,
    };

    let mut header = Header::default();
    header.kid = Some("1dea0016-46b8-4289-ad7b-226cfaf5305e".to_string());
    header.alg = Algorithm::RS256;

    let token = jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(include_bytes!("jwt.key"))
            .expect("Failed to create encoding key"),
    )
    .expect("Failed to create token");

    let result: TokenData<CustomClaims> = decoder.decode(&token).expect("Failed to decode token");
    assert_eq!(result.claims.iat, claims.iat);
    assert_eq!(result.claims.aud, claims.aud);
    assert!(result.claims.exp > Utc::now().timestamp() as u64);

    // Test decoding with expired token
    let expired_claims = CustomClaims {
        iat: 1234567890,
        aud: "https://example.com".to_string(),
        exp: (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp() as u64,
    };

    let expired_token = jsonwebtoken::encode(
        &Header::new(Algorithm::RS256),
        &expired_claims,
        &EncodingKey::from_rsa_pem(include_bytes!("jwt.key"))
            .expect("Failed to create encoding key"),
    )
    .expect("Failed to create token");

    let expired_result: Result<TokenData<CustomClaims>, _> = decoder.decode(&expired_token);
    assert!(expired_result.is_err());

    // Clean up
    server_handle.abort();
    refresh_handle.abort();
}
