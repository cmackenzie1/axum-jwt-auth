//! Provides a thin layer over jsonwebtoken crate to manage remote JWKS and local secret keys.

mod axum;
mod remote;

use async_trait::async_trait;
use jsonwebtoken::TokenData;
use serde::de::DeserializeOwned;

pub use crate::axum::{AuthError, Claims, JwtDecoderState};
pub use crate::remote::{RemoteJwksDecoder, RemoteJwksDecoderBuilder};

#[derive(Debug)]
pub enum Error {
    KeyNotFound(Option<String>),
    Jwt(jsonwebtoken::errors::Error),
    Reqwest(reqwest::Error),
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

/// aA trait for decoding JWT tokens.
#[async_trait]
pub trait JwtDecoder<T>
where
    T: for<'de> DeserializeOwned,
{
    fn decode(&self, token: &str) -> Result<TokenData<T>, Error>;
}
