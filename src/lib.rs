//! A Rust library for JWT authentication with support for both local keys and remote JWKS (JSON Web Key Sets).
//!
//! This crate provides a flexible JWT authentication system that can:
//! - Validate tokens using local RSA/HMAC keys
//! - Automatically fetch and cache remote JWKS endpoints
//! - Integrate seamlessly with the Axum web framework
//! - Handle token validation with configurable options
//!
//! It builds on top of the `jsonwebtoken` crate to provide higher-level authentication primitives
//! while maintaining full compatibility with standard JWT implementations.
//!
//! # Example
//!
//! ```rust
//! use axum::{
//!     extract::FromRef,
//!     response::{IntoResponse, Response},
//!     routing::{get, post},
//!     Json, Router,
//! };
//!
//! use chrono::{Duration, Utc};
//! use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
//! use axum_jwt_auth::{Claims, Decoder, JwtDecoderState, LocalDecoder};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Clone, FromRef)]
//! struct AppState {
//!     decoder: JwtDecoderState,
//! }
//!
//! #[derive(Debug, Serialize, Deserialize)]
//! pub struct MyClaims {
//!     iat: u64,
//!     aud: String,
//!     exp: u64,
//! }
//!
//! async fn index() -> Response {
//!     "Hello, World!".into_response()
//! }
//!
//! // Claims extractor will return a 401 if the token is invalid
//! async fn user_info(Claims(claims): Claims<MyClaims>) -> Response {
//!     Json(claims).into_response()
//! }
//!
//! async fn login() -> Response {
//!     let key = EncodingKey::from_rsa_pem(include_bytes!("../jwt.key")).expect("valid RSA key");
//!     let mut header = Header::new(Algorithm::RS256);
//!     header.kid = Some("test".to_string());
//!
//!     let exp = Utc::now() + Duration::hours(1);
//!     let claims = MyClaims {
//!         iat: 1234567890,
//!         aud: "https://example.com".to_string(),
//!         exp: exp.timestamp() as u64,
//!     };
//!
//!     let token = encode::<MyClaims>(&header, &claims, &key).expect("token creation");
//!
//!     token.into_response()
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     let keys = vec![DecodingKey::from_rsa_pem(include_bytes!("jwt.key.pub")).expect("valid public key")];
//!     let mut validation = Validation::new(Algorithm::RS256);
//!     // Set the audience to the expected value. Not setting this will cause the token to be invalid.
//!     validation.set_audience(&["https://example.com"]);
//!     let decoder: Decoder = LocalDecoder::new(keys, validation).into();
//!     let state = AppState {
//!         decoder: JwtDecoderState { decoder },
//!     };
//!
//!     let app = Router::new()
//!         .route("/", get(index))
//!         .route("/user_info", get(user_info))
//!         .route("/login", post(login))
//!         .with_state(state);
//!
//!     # // Commented out to make doctests pass
//!     # // run it on localhost:3000
//!     # // let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
//!     # // axum::serve(listener, app).await.unwrap();
//! }
//! ```
//!

mod axum;
mod local;
mod remote;

use std::sync::Arc;

use jsonwebtoken::TokenData;
use serde::de::DeserializeOwned;
use thiserror::Error;

pub use crate::axum::{AuthError, Claims, JwtDecoderState};
pub use crate::local::LocalDecoder;
pub use crate::remote::{RemoteJwksDecoder, RemoteJwksDecoderBuilder};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("JWT key not found (kid: {0:?})")]
    KeyNotFound(Option<String>),
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("HTTP request error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("JWKS refresh failed: {0}")]
    JwksRefresh(String),
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Self::Reqwest(err)
    }
}

impl From<jsonwebtoken::errors::Error> for Error {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        Self::Jwt(err)
    }
}

/// A generic trait for decoding JWT tokens.
///
/// This trait is implemented for both `LocalDecoder` and `RemoteJwksDecoder`
pub trait JwtDecoder<T>
where
    T: for<'de> DeserializeOwned,
{
    fn decode(&self, token: &str) -> Result<TokenData<T>, Error>;
}

#[derive(Clone)]
pub enum Decoder {
    Local(Arc<LocalDecoder>),
    Remote(Arc<RemoteJwksDecoder>),
}

impl<T: DeserializeOwned> JwtDecoder<T> for Decoder {
    fn decode(&self, token: &str) -> Result<TokenData<T>, Error> {
        match self {
            Self::Local(decoder) => decoder.decode(token),
            Self::Remote(decoder) => decoder.decode(token),
        }
    }
}
