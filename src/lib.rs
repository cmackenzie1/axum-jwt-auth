//! A Rust library for JWT authentication with support for both local keys and remote JWKS (JSON Web Key Sets).
//!
//! This crate provides a flexible JWT authentication system that can:
//! - Validate tokens using local RSA/HMAC keys
//! - Automatically fetch and cache remote JWKS endpoints
//! - Integrate seamlessly with the Axum web framework
//! - Handle token validation with configurable options
//! - Extract tokens from multiple sources (headers, cookies, query parameters)
//!
//! It builds on top of the `jsonwebtoken` crate to provide higher-level authentication primitives
//! while maintaining full compatibility with standard JWT implementations.
//!
//! # Quick Start
//!
//! ## Using Bearer Tokens (Default)
//!
//! ```ignore
//! use axum::{Router, routing::get, Json};
//! use axum_jwt_auth::{Claims, LocalDecoder, JwtDecoderState};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Deserialize, Serialize)]
//! struct MyClaims {
//!     sub: String,
//!     exp: usize,
//! }
//!
//! async fn protected_handler(user: Claims<MyClaims>) -> Json<MyClaims> {
//!     Json(user.claims)
//! }
//! ```
//!
//! ## Custom Token Extractors
//!
//! Use macros to easily define custom extractors:
//!
//! ```ignore
//! use axum_jwt_auth::{define_header_extractor, define_cookie_extractor, define_query_extractor};
//! use axum_jwt_auth::{Claims, HeaderTokenExtractor, CookieTokenExtractor, QueryTokenExtractor};
//!
//! // Define custom extractors
//! define_header_extractor!(XAuthToken, "x-auth-token");
//! define_cookie_extractor!(AuthCookie, "auth_token");
//! define_query_extractor!(TokenParam, "token");
//!
//! // Use in handlers
//! async fn header_handler(user: Claims<MyClaims, HeaderTokenExtractor<XAuthToken>>) {
//!     // Token extracted from "x-auth-token" header
//! }
//!
//! async fn cookie_handler(user: Claims<MyClaims, CookieTokenExtractor<AuthCookie>>) {
//!     // Token extracted from "auth_token" cookie
//! }
//!
//! async fn query_handler(user: Claims<MyClaims, QueryTokenExtractor<TokenParam>>) {
//!     // Token extracted from "?token=..." query parameter
//! }
//! ```
//!
//! # Examples
//!
//! For full examples, see the [examples directory](https://github.com/cmackenzie1/axum-jwt-auth/blob/main/examples).

mod axum;
mod local;
mod remote;

use std::sync::Arc;

use async_trait::async_trait;
use jsonwebtoken::TokenData;
use serde::de::DeserializeOwned;
use thiserror::Error;

pub use crate::axum::{
    AuthError, BearerTokenExtractor, Claims, CookieTokenExtractor, ExtractorConfig,
    HeaderTokenExtractor, JwtDecoderState, QueryTokenExtractor, TokenExtractor,
};
pub use crate::local::LocalDecoder;
pub use crate::remote::{
    RemoteJwksDecoder, RemoteJwksDecoderBuilder, RemoteJwksDecoderConfig,
    RemoteJwksDecoderConfigBuilder,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("JWT key not found (kid: {0:?})")]
    KeyNotFound(Option<String>),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("HTTP request error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("JWKS refresh failed after {retry_count} attempts: {message}")]
    JwksRefresh {
        message: String,
        retry_count: usize,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

/// A generic trait for decoding JWT tokens.
///
/// This trait is implemented for both `LocalDecoder` and `RemoteJwksDecoder`
#[async_trait]
pub trait JwtDecoder<T>
where
    T: for<'de> DeserializeOwned,
{
    async fn decode(&self, token: &str) -> Result<TokenData<T>, Error>;
}

/// A type alias for a decoder that can be used as a state in an Axum application.
pub type Decoder<T> = Arc<dyn JwtDecoder<T> + Send + Sync>;
