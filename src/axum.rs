use async_trait::async_trait;
use axum::extract::FromRef;
use axum::http::StatusCode;
use axum::response::Response;
use axum::RequestPartsExt;
use axum::{http::request::Parts, response::IntoResponse};
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::TypedHeader;
use jsonwebtoken::errors::ErrorKind;
use serde::de::DeserializeOwned;
use serde::Deserialize;

use crate::Decoder;

/// A generic struct for holding the claims of a JWT token.
#[derive(Debug, Deserialize)]
pub struct Claims<T>(pub T);

/// Trait for extracting tokens from request parts
#[async_trait]
pub trait TokenExtractor {
    async fn extract_token(parts: &mut Parts) -> Result<String, AuthError>;
}

/// Default implementation using Bearer token
pub struct BearerTokenExtractor;

#[async_trait]
impl TokenExtractor for BearerTokenExtractor {
    async fn extract_token(parts: &mut Parts) -> Result<String, AuthError> {
        let auth: TypedHeader<Authorization<Bearer>> =
            parts.extract().await.map_err(|_| AuthError::MissingToken)?;

        Ok(auth.token().to_string())
    }
}

impl<S, T> axum::extract::FromRequestParts<S> for Claims<T>
where
    JwtDecoderState<T>: FromRef<S>,
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // TODO: Allow for custom token extractors?
        let token = BearerTokenExtractor::extract_token(parts).await?;

        let state = JwtDecoderState::from_ref(state);
        let token_data = state
            .decoder
            .clone()
            .decode(&token)
            .await
            .map_err(map_jwt_error)?;

        Ok(Claims(token_data.claims))
    }
}

/// Maps JWT errors to AuthError
fn map_jwt_error(err: crate::Error) -> AuthError {
    match err {
        crate::Error::Jwt(e) => match e.kind() {
            ErrorKind::ExpiredSignature => AuthError::ExpiredSignature,
            ErrorKind::InvalidSignature => AuthError::InvalidSignature,
            ErrorKind::InvalidAudience => AuthError::InvalidAudience,
            ErrorKind::InvalidAlgorithm => AuthError::InvalidAlgorithm,
            ErrorKind::InvalidToken => AuthError::InvalidToken,
            ErrorKind::InvalidIssuer => AuthError::InvalidIssuer,
            ErrorKind::InvalidSubject => AuthError::InvalidSubject,
            ErrorKind::ImmatureSignature => AuthError::ImmatureSignature,
            ErrorKind::MissingAlgorithm => AuthError::MissingAlgorithm,
            ErrorKind::MissingRequiredClaim(claim) => {
                AuthError::MissingRequiredClaim(claim.to_string())
            }
            _ => AuthError::InternalError,
        },
        _ => AuthError::InternalError,
    }
}

/// An enum representing the possible errors that can occur when authenticating a request.
/// These are sourced from the `jsonwebtoken` crate and defined here to implement `IntoResponse` for
/// use in the `axum` framework.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum AuthError {
    /// When the token is invalid
    #[error("Invalid token")]
    InvalidToken,

    /// When the signature is invalid
    #[error("Invalid signature")]
    InvalidSignature,

    // Validation errors
    /// When a claim required by the validation is not present
    #[error("Missing required claim: {0}")]
    MissingRequiredClaim(String),

    /// When a token's `exp` claim indicates that it has expired
    #[error("Expired signature")]
    ExpiredSignature,

    /// When a token's `iss` claim does not match the expected issuer
    #[error("Invalid issuer")]
    InvalidIssuer,

    /// When a token's `aud` claim does not match one of the expected audience values
    #[error("Invalid audience")]
    InvalidAudience,

    /// When a token's `sub` claim does not match one of the expected subject values
    #[error("Invalid subject")]
    InvalidSubject,

    /// When a token's `nbf` claim represents a time in the future
    #[error("Immature signature")]
    ImmatureSignature,

    /// When the algorithm in the header doesn't match the one passed to `decode` or the encoding/decoding key
    /// used doesn't match the alg requested
    #[error("Invalid algorithm")]
    InvalidAlgorithm,

    /// When the Validation struct does not contain at least 1 algorithm
    #[error("Missing algorithm")]
    MissingAlgorithm,

    /// When the request is missing a token
    #[error("Missing token")]
    MissingToken,

    /// When an internal error occurs that doesn't fit into the other categories.
    /// This is a catch-all error for any unexpected errors that occur such as
    /// network errors, decoding errors, and cryptographic errors.
    #[error("Internal error")]
    InternalError,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthError::InvalidSignature => (StatusCode::UNAUTHORIZED, "Invalid signature"),
            AuthError::MissingRequiredClaim(_) => {
                (StatusCode::UNAUTHORIZED, "Missing required claim")
            }
            AuthError::ExpiredSignature => (StatusCode::UNAUTHORIZED, "Expired signature"),
            AuthError::InvalidIssuer => (StatusCode::UNAUTHORIZED, "Invalid issuer"),
            AuthError::InvalidAudience => (StatusCode::UNAUTHORIZED, "Invalid audience"),
            AuthError::InvalidSubject => (StatusCode::UNAUTHORIZED, "Invalid subject"),
            AuthError::ImmatureSignature => (StatusCode::UNAUTHORIZED, "Immature signature"),
            AuthError::InvalidAlgorithm => (StatusCode::UNAUTHORIZED, "Invalid algorithm"),
            AuthError::MissingAlgorithm => (StatusCode::UNAUTHORIZED, "Missing algorithm"),
            AuthError::MissingToken => (StatusCode::UNAUTHORIZED, "Missing token"),
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

#[cfg(test)]
mod tests {

    use super::*;
    use axum::body::Body;
    use axum::extract::Request;

    #[tokio::test]
    async fn test_map_jwt_error() {
        use jsonwebtoken::errors::Error as JwtError;

        let jwt_error = JwtError::from(ErrorKind::ExpiredSignature);
        let auth_error = map_jwt_error(crate::Error::Jwt(jwt_error));
        assert!(matches!(auth_error, AuthError::ExpiredSignature));
    }

    #[tokio::test]
    async fn test_bearer_token_extractor() {
        // Valid token
        let req = Request::builder()
            .header("Authorization", "Bearer test_token")
            .body(Body::empty())
            .unwrap();

        let token = BearerTokenExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_ok());
        assert_eq!(token.unwrap(), "test_token");

        // Invalid token
        let req = Request::builder()
            .header("Authorization", "Not a bearer token")
            .body(Body::empty())
            .unwrap();

        let token = BearerTokenExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_err());
        assert_eq!(token.unwrap_err(), AuthError::MissingToken);

        // Missing token
        let req = Request::builder().body(Body::empty()).unwrap();
        let token = BearerTokenExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_err());
        assert_eq!(token.unwrap_err(), AuthError::MissingToken);
    }
}
