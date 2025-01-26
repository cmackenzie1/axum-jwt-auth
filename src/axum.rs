use axum::extract::FromRef;
use axum::http::StatusCode;
use axum::response::Response;
use axum::RequestPartsExt;
use axum::{http::request::Parts, response::IntoResponse};
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::TypedHeader;
use serde::de::DeserializeOwned;
use serde::Deserialize;

use crate::Decoder;

/// A generic struct for holding the claims of a JWT token.
#[derive(Debug, Deserialize)]
pub struct Claims<T>(pub T);

impl<S, T> axum::extract::FromRequestParts<S> for Claims<T>
where
    JwtDecoderState<T>: FromRef<S>,
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // `TypedHeader<Authorization<Bearer>>` extracts the auth token
        let auth: TypedHeader<Authorization<Bearer>> = parts
            .extract()
            .await
            .map_err(|_| Self::Rejection::MissingToken)?;

        let state = JwtDecoderState::from_ref(state);
        // `JwtDecoder::decode` decodes the token
        let token_data = state
            .decoder
            .clone()
            .decode(auth.token())
            .await
            .map_err(|e| match e {
                crate::Error::Jwt(e) => match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                        Self::Rejection::ExpiredToken
                    }
                    jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                        Self::Rejection::InvalidSignature
                    }
                    jsonwebtoken::errors::ErrorKind::InvalidAudience => {
                        Self::Rejection::InvalidAudience
                    }
                    _ => Self::Rejection::InvalidToken,
                },
                _ => Self::Rejection::InternalError,
            })?;

        Ok(Claims(token_data.claims))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid token")]
    InvalidToken,
    #[error("Missing token")]
    MissingToken,
    #[error("Expired token")]
    ExpiredToken,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid audience")]
    InvalidAudience,
    #[error("Internal error")]
    InternalError,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthError::MissingToken => (StatusCode::UNAUTHORIZED, "Missing token"),
            AuthError::ExpiredToken => (StatusCode::UNAUTHORIZED, "Expired token"),
            AuthError::InvalidSignature => (StatusCode::UNAUTHORIZED, "Invalid signature"),
            AuthError::InvalidAudience => (StatusCode::UNAUTHORIZED, "Invalid audience"),
            AuthError::InternalError => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
        };

        (status, msg).into_response()
    }
}

#[derive(Clone)]
pub struct JwtDecoderState<T> {
    pub decoder: Decoder<T>,
}

impl<T> FromRef<JwtDecoderState<T>> for Decoder<T> {
    fn from_ref(state: &JwtDecoderState<T>) -> Self {
        state.decoder.clone()
    }
}
