use std::{sync::Arc, time::Duration};

use axum::{routing::get, Json, Router};
use axum_jwt_auth::{
    JwtDecoder, RemoteJwksDecoder, RemoteJwksDecoderBuilder, RemoteJwksDecoderConfigBuilder,
};
use dashmap::DashMap;
use jsonwebtoken::{Algorithm, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct CustomClaims {
    sub: String,
    name: String,
    exp: usize,
}

// This is a sample JWKS handler. In a real application, you would fetch the JWKS from a remote source.
// For testing purposes, we randomly fail 50% of the time to simulate a remote JWKS endpoint that is not available.
async fn jwks_handler() -> Json<Value> {
    // Randomly fail 50% of the time
    if rand::random::<bool>() {
        return Json(json!({
            "error": "Internal Server Error",
            "message": "Random failure for testing"
        }));
    }

    // This is a sample JWKS. In a real application, you would generate proper keys or fetch them from a remote source
    Json(json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "1dea0016-46b8-4289-ad7b-226cfaf5305e",
            "n": "sPWeaqsN-2KZu9rlto59XASssMoaVjIxMYXtLyifky1sXS4EvYFnvr37X63B-lMwuZ3xACc7xsUPK-GXPe6XqZGJdj-Wgf7a3J6FieSNpnrDK4x6CMr0iAPgIhoEYp7BUyPKzPv21vMl6A5kJvlAAdxfPm3jhk5NDWHSfiFnWiC7UESARgyFl0TlJ-f9H3qaArkzp3Cb-m-wlHpleewOSr9maTPLdIS-ZzZ1ZC4lDIQnetJJ0kue-o1wAL4VmdBMY8IVxEutPAaZO-9G8eYJywZiDDkcrrqWymDvSUarcB_AOzEQjxN6nSSNuW6UbalfnDlGmR0kFK8fopraA4nwU4tG6fAuKTPpOmahC910IRAkedOp6IrRU-2LmcBQ0oyzukHjXd9o9_5MES2wTDFgZBalVRZCo55vdQt5CtQDQWVUbQ1y95dm_0EmmgZzWBgiguSKcO2QuqwYIiq5t9uikFleeVQDVnd-V6yZ5wWfnA6H0-dPw4VTEUkxaTN8jQImQtB9gvj8iknsGX08LGF5WjWh1ewJI0L74Ey5T_ytsXME6Xpn1qfXB2sr5tPol3KeV8pjuGrAymvaLJZz4ZqNY3f4wULfCsyVasUOdknMm8UmTgPR-vnDlF-1ItsmN-Jl-RJ1dFkXRDcelCIJS44sMSchnxv47OwnqvBHCPbiUI8",
            "e": "AQAB"
          }]
    }))
}

#[tokio::main]
async fn main() {
    // Initialize tracing for logging
    tracing_subscriber::fmt::init();

    // Create the Axum router with the JWKS endpoint
    let app = Router::new().route("/.well-known/jwks.json", get(jwks_handler));

    // Spawn the server task
    let server_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
            .await
            .expect("Failed to bind server");
        println!("JWKS server listening on http://127.0.0.1:3000");
        axum::serve(listener, app)
            .await
            .expect("Failed to start server");
    });

    // Create a remote JWKS decoder with custom configuration
    let decoder = RemoteJwksDecoderBuilder::default()
        .jwks_url("http://127.0.0.1:3000/.well-known/jwks.json".to_string())
        .config(
            RemoteJwksDecoderConfigBuilder::default()
                .cache_duration(Duration::from_secs(1)) // Low value for testing, in a real application you should use a higher value
                .retry_count(3)
                .backoff(Duration::from_secs(1))
                .build()
                .unwrap(),
        )
        .validation(Validation::new(Algorithm::RS256))
        .client(reqwest::Client::new())
        .keys_cache(Arc::new(DashMap::new()))
        .build()
        .expect("Failed to build decoder");

    // Spawn a task to periodically refresh the JWKS
    let decoder_clone = decoder.clone();
    tokio::spawn(async move {
        decoder_clone.refresh_keys_periodically().await;
    });

    // Create a token
    let token = jsonwebtoken::encode(
        &Header::new(Algorithm::RS256),
        &CustomClaims {
            sub: "123".to_string(),
            name: "John Doe".to_string(),
            exp: (chrono::Utc::now().timestamp() + 60 * 60) as usize,
        },
        &EncodingKey::from_rsa_pem(include_bytes!("jwt.key")).unwrap(),
    )
    .unwrap();

    // Decode the token
    match <RemoteJwksDecoder as JwtDecoder<CustomClaims>>::decode(&decoder, &token) {
        Ok(token_data) => {
            println!("Token successfully decoded: {:?}", token_data.claims);
        }
        Err(err) => {
            eprintln!("Failed to decode token: {:?}", err);
        }
    }

    // Keep the main task running for a while to see the periodic refresh in action
    tokio::time::sleep(Duration::from_secs(60)).await;

    // Clean shutdown
    server_handle.abort();
}
