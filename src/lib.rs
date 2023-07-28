//! Provides a thin layer over jsonwebtoken crate to manage remote JWKS and local secret keys.

mod axum;
mod local;
mod remote;

use std::sync::Arc;

use jsonwebtoken::TokenData;
use serde::de::DeserializeOwned;

pub use crate::axum::{AuthError, Claims, JwtDecoderState};
pub use crate::local::LocalDecoder;
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

/// A trait for decoding JWT tokens.
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
