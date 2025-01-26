use std::sync::Arc;

use axum::{
    extract::FromRef,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};

use axum_jwt_auth::{
    Claims, Decoder, JwtDecoder, JwtDecoderState, LocalDecoder, RemoteJwksDecoder,
    RemoteJwksDecoderConfig,
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

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
}

#[tokio::test]
async fn local_decoder() {
    // Initialize tracing for logging, with a guard to prevent duplicate initialization
    init_tracing();

    // Load the keys
    let encoding_key = EncodingKey::from_rsa_pem(include_bytes!("jwt.key")).unwrap();
    let decoding_key = DecodingKey::from_rsa_pem(include_bytes!("jwt.key.pub")).unwrap();

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&["https://example.com"]);

    let decoder: Decoder<CustomClaims> = Arc::new(
        LocalDecoder::builder()
            .keys(vec![decoding_key.to_owned()])
            .validation(validation)
            .build()
            .unwrap(),
    );
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

                let claims = CustomClaims {
                    iat: Utc::now().timestamp() as u64,
                    aud: "https://example.com".to_string(),
                    exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
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
    assert!(claims.iat <= Utc::now().timestamp() as u64);
    assert!(claims.exp >= Utc::now().timestamp() as u64);
}

#[tokio::test]
async fn remote_decoder() {
    init_tracing();

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
    let decoder = RemoteJwksDecoder::builder()
        .jwks_url("http://127.0.0.1:3001/.well-known/jwks.json".to_string())
        .config(
            RemoteJwksDecoderConfig::builder()
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

    // Test decoding with valid token
    let claims = CustomClaims {
        iat: 1234567890,
        aud: "https://example.com".to_string(),
        exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as u64,
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("1dea0016-46b8-4289-ad7b-226cfaf5305e".to_string());

    let token = jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(include_bytes!("jwt.key"))
            .expect("Failed to create encoding key"),
    )
    .expect("Failed to create token");

    let result: TokenData<CustomClaims> = decoder
        .decode(&token)
        .await
        .expect("Failed to decode token");
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

    let expired_result: Result<TokenData<CustomClaims>, _> = decoder.decode(&expired_token).await;
    assert!(expired_result.is_err());

    // Clean up
    server_handle.abort();
    refresh_handle.abort();
}

#[tokio::test]
async fn test_remote_decoder_initialization() {
    init_tracing();

    // Create a delayed JWKS handler that simulates slow responses
    let app = Router::new().route(
        "/.well-known/jwks.json",
        get(|| async {
            // Simulate slow initial response
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            Json(json!({
                "keys": [{
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": "test-key",
                    "n": "sPWeaqsN-2KZu9rlto59XASssMoaVjIxMYXtLyifky1sXS4EvYFnvr37X63B-lMwuZ3xACc7xsUPK-GXPe6XqZGJdj-Wgf7a3J6FieSNpnrDK4x6CMr0iAPgIhoEYp7BUyPKzPv21vMl6A5kJvlAAdxfPm3jhk5NDWHSfiFnWiC7UESARgyFl0TlJ-f9H3qaArkzp3Cb-m-wlHpleewOSr9maTPLdIS-ZzZ1ZC4lDIQnetJJ0kue-o1wAL4VmdBMY8IVxEutPAaZO-9G8eYJywZiDDkcrrqWymDvSUarcB_AOzEQjxN6nSSNuW6UbalfnDlGmR0kFK8fopraA4nwU4tG6fAuKTPpOmahC910IRAkedOp6IrRU-2LmcBQ0oyzukHjXd9o9_5MES2wTDFgZBalVRZCo55vdQt5CtQDQWVUbQ1y95dm_0EmmgZzWBgiguSKcO2QuqwYIiq5t9uikFleeVQDVnd-V6yZ5wWfnA6H0-dPw4VTEUkxaTN8jQImQtB9gvj8iknsGX08LGF5WjWh1ewJI0L74Ey5T_ytsXME6Xpn1qfXB2sr5tPol3KeV8pjuGrAymvaLJZz4ZqNY3f4wULfCsyVasUOdknMm8UmTgPR-vnDlF-1ItsmN-Jl-RJ1dFkXRDcelCIJS44sMSchnxv47OwnqvBHCPbiUI8",
                    "e": "AQAB"
                }]
            }))
        }),
    );

    // Spawn the JWKS server
    let server_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:3002")
            .await
            .expect("Failed to bind JWKS server");
        axum::serve(listener, app).await.unwrap();
    });

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&["https://example.com"]);

    let decoder = RemoteJwksDecoder::builder()
        .jwks_url("http://127.0.0.1:3002/.well-known/jwks.json".to_string())
        .config(
            RemoteJwksDecoderConfig::builder()
                .cache_duration(Duration::seconds(5).to_std().unwrap())
                .retry_count(1)
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

    // Create multiple concurrent decode attempts
    let start = std::time::Instant::now();

    let mut handles = vec![];
    for i in 0..3 {
        let decoder = decoder.clone();
        let handle = tokio::spawn(async move {
            let token = format!("invalid_token_{}", i);
            let _: Result<TokenData<CustomClaims>, _> = decoder.decode(&token).await; // We expect this to fail, but after initialization
            std::time::Instant::now()
        });
        handles.push(handle);
    }

    // Wait for all decode attempts
    let completion_times = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect::<Vec<_>>();

    // All tasks should complete at roughly the same time (after the initial 2-second delay)
    for time in &completion_times {
        let elapsed = time.duration_since(start);
        assert!(elapsed.as_secs() >= 2, "Task completed too quickly");
        // Should complete very soon after initialization
        assert!(elapsed.as_secs() < 3, "Task took too long to complete");
    }

    // Verify that max difference between completion times is small
    let max_time = completion_times.iter().max().unwrap();
    let min_time = completion_times.iter().min().unwrap();
    let max_diff = max_time.duration_since(*min_time);
    assert!(max_diff.as_millis() < 100, "Tasks completed too far apart");

    // Clean up
    server_handle.abort();
    refresh_handle.abort();
}
