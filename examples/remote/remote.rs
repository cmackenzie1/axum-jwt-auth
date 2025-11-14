use std::sync::Arc;

use axum::{extract::FromRef, routing::get, Json, Router};
use axum_jwt_auth::{Claims, JwtDecoderState, RemoteJwksDecoder};
use jsonwebtoken::{Algorithm, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

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

/// This is a protected route that requires a valid JWT token to be passed in the Authorization header
/// It uses the `Claims` extractor to get the claims from the token
async fn protected_route(user: Claims<CustomClaims>) -> Json<CustomClaims> {
    Json(user.claims)
}

/// This is a state struct that holds the JWT decoder
#[derive(Clone, FromRef)]
struct AppState {
    decoder: JwtDecoderState<CustomClaims>,
}

#[tokio::main]
async fn main() {
    // Initialize tracing for logging
    tracing_subscriber::fmt::init();

    // First, we need to mock a JWKS server for testing purposes
    // In a real application, this would be a remote server like auth0, okta, etc.
    let jwks_server = Router::new().route("/.well-known/jwks.json", get(jwks_handler));
    let server_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
            .await
            .expect("Failed to bind JWKS mock server");
        println!("Mock JWKS server listening on http://127.0.0.1:3000");
        axum::serve(listener, jwks_server)
            .await
            .expect("Failed to start JWKS mock server");
    });

    // Set the validation parameters, as of jsonwebtoken version 9, you MUST set the algorithm and the audience
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&["your-audience"]);
    validation.set_issuer(&["your-issuer"]);

    // Create a decoder pointing to the JWKS endpoint
    let decoder = RemoteJwksDecoder::builder()
        .jwks_url("http://127.0.0.1:3000/.well-known/jwks.json".to_string())
        .validation(validation)
        .build()
        .expect("Failed to build JWKS decoder");
    let decoder = Arc::new(decoder);

    // Start background task to periodically refresh JWKS
    let decoder_clone = decoder.clone();
    tokio::spawn(async move {
        decoder_clone.refresh_keys_periodically().await;
    });

    // Create an app server that has the decoder as a state
    let app_server = Router::new()
        .route("/protected", get(protected_route))
        .with_state(AppState {
            decoder: JwtDecoderState {
                decoder: decoder.clone(),
            },
        });

    // Start the app server
    let app_server_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:3001")
            .await
            .expect("Failed to bind app server");
        println!("App server listening on http://127.0.0.1:3001");
        axum::serve(listener, app_server)
            .await
            .expect("Failed to start app server");
    });

    // Example: Validate a JWT token
    // In a real application, this token would come from your users
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("1dea0016-46b8-4289-ad7b-226cfaf5305e".to_string());

    let test_token = jsonwebtoken::encode(
        &header,
        &CustomClaims {
            sub: "user123".to_string(),
            name: "Test User".to_string(),
            exp: (chrono::Utc::now().timestamp() + 3600) as usize, // 1 hour expiry
        },
        &EncodingKey::from_rsa_pem(include_bytes!("jwt.key")).unwrap(),
    )
    .expect("Failed to create test token");

    // Make a request to the protected route
    let response = reqwest::Client::new()
        .get("http://127.0.0.1:3001/protected")
        .header("Authorization", format!("Bearer {}", test_token))
        .send()
        .await
        .expect("Failed to make request");
    println!(
        "Response: {:?}",
        response
            .json::<CustomClaims>()
            .await
            .expect("Failed to read response")
    );

    // Clean up our servers
    server_handle.abort();
    app_server_handle.abort();
}
