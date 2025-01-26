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
//! For a full example, see the [examples](https://github.com/cmackenzie1/axum-jwt-auth/blob/main/examples).

mod axum;
mod local;
mod remote;

use std::sync::Arc;

use async_trait::async_trait;
use jsonwebtoken::TokenData;
use serde::de::DeserializeOwned;
use thiserror::Error;

pub use crate::axum::{AuthError, Claims, JwtDecoderState};
pub use crate::local::LocalDecoder;
pub use crate::remote::{
    RemoteJwksDecoder, RemoteJwksDecoderBuilder, RemoteJwksDecoderConfig,
    RemoteJwksDecoderConfigBuilder,
};

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
