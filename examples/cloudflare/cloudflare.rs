use std::sync::Arc;

use axum::{
    Json, Router,
    extract::FromRef,
    response::{IntoResponse, Response},
    routing::get,
};
use axum_jwt_auth::{
    Claims, CookieTokenExtractor, Decoder, HeaderTokenExtractor, RemoteJwksDecoder,
    define_cookie_extractor, define_header_extractor,
};
use jsonwebtoken::{Algorithm, Validation};
use serde::{Deserialize, Serialize};

/// Cloudflare Access JWT Claims
/// See: https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CloudflareAccessClaims {
    /// Audience - your Cloudflare Access application AUD
    pub aud: Vec<String>,
    /// Email of the authenticated user
    pub email: String,
    /// Expiration time
    pub exp: usize,
    /// Issued at time
    pub iat: usize,
    /// Not before time
    pub nbf: usize,
    /// Issuer - your Cloudflare team domain
    pub iss: String,
    /// Type - should be "app"
    #[serde(rename = "type")]
    pub token_type: String,
    /// Identity nonce
    pub identity_nonce: String,
    /// Subject - user ID
    pub sub: String,
    /// Custom claims (optional)
    #[serde(flatten)]
    pub custom: std::collections::HashMap<String, serde_json::Value>,
}

// Define Cloudflare Access extractors using the convenience macros
define_header_extractor!(CfAccessJwtHeader, "cf-access-jwt-assertion");
define_cookie_extractor!(CfAuthCookie, "CF_Authorization");

/// This is a state struct that holds the JWT decoder
#[derive(Clone, FromRef)]
struct AppState {
    decoder: Decoder<CloudflareAccessClaims>,
}

/// Public route - no authentication required
async fn public_route() -> &'static str {
    "This route is publicly accessible"
}

/// Protected route using Cloudflare Access JWT from header
/// This is the recommended approach for programmatic access (API clients)
async fn protected_header_route(
    user: Claims<CloudflareAccessClaims, HeaderTokenExtractor<CfAccessJwtHeader>>,
) -> Json<CloudflareAccessClaims> {
    Json(user.claims)
}

/// Protected route using Cloudflare Access JWT from cookie
/// This is the default for browser-based access
async fn protected_cookie_route(
    user: Claims<CloudflareAccessClaims, CookieTokenExtractor<CfAuthCookie>>,
) -> Json<CloudflareAccessClaims> {
    Json(user.claims)
}

/// Protected route that accepts either header or cookie
/// This demonstrates accessing the claims field
async fn protected_flexible_route(
    // You can use either extractor type depending on your needs
    user: Claims<CloudflareAccessClaims, HeaderTokenExtractor<CfAccessJwtHeader>>,
) -> Response {
    let response = serde_json::json!({
        "email": user.claims.email,
        "user_id": user.claims.sub,
        "authenticated_via": "cloudflare_access"
    });
    Json(response).into_response()
}

#[tokio::main]
async fn main() {
    // Initialize tracing for logging
    tracing_subscriber::fmt::init();

    // Cloudflare Access configuration
    // Replace these with your actual values from the Cloudflare Zero Trust dashboard
    let team_domain = std::env::var("CF_TEAM_DOMAIN")
        .unwrap_or_else(|_| "your-team.cloudflareaccess.com".to_string());
    let audience = std::env::var("CF_AUD").unwrap_or_else(|_| "your-app-aud".to_string());

    // Cloudflare Access JWKS URL format
    let jwks_url = format!("https://{}/cdn-cgi/access/certs", team_domain);

    println!("Cloudflare Access Configuration:");
    println!("  Team Domain: {}", team_domain);
    println!("  JWKS URL: {}", jwks_url);
    println!("  Audience: {}", audience);

    // Configure validation for Cloudflare Access
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[&audience]);
    validation.set_issuer(&[&format!("https://{}", team_domain)]);

    // Create a decoder pointing to the Cloudflare Access JWKS endpoint
    let decoder = RemoteJwksDecoder::builder()
        .jwks_url(jwks_url)
        .validation(validation)
        .build()
        .expect("Failed to build JWKS decoder");

    let decoder = Arc::new(decoder);

    // Initialize: fetch keys immediately and start background refresh task
    let _shutdown_token = decoder
        .initialize()
        .await
        .expect("Failed to initialize JWKS decoder");

    // Create application state
    let state = AppState {
        decoder: decoder.clone(),
    };

    // Build the application with routes
    let app = Router::new()
        .route("/", get(public_route))
        .route("/api/header", get(protected_header_route))
        .route("/api/cookie", get(protected_cookie_route))
        .route("/api/user", get(protected_flexible_route))
        .with_state(state);

    // Run the server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("Failed to bind");

    println!("\n🚀 Server running on http://127.0.0.1:3000");
    println!("\nAvailable endpoints:");
    println!("  GET /           - Public route (no auth required)");
    println!("  GET /api/header - Protected route (requires Cf-Access-Jwt-Assertion header)");
    println!("  GET /api/cookie - Protected route (requires CF_Authorization cookie)");
    println!("  GET /api/user   - Protected route (returns user info)");
    println!("\n📝 Note: This example requires a Cloudflare Access application to be configured.");
    println!("   Set CF_TEAM_DOMAIN and CF_AUD environment variables to test with your setup.");

    axum::serve(listener, app)
        .await
        .expect("Failed to start server");
}
