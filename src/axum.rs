use std::marker::PhantomData;

use async_trait::async_trait;
use axum::extract::FromRef;
use axum::http::{header::HeaderName, StatusCode};
use axum::response::Response;
use axum::RequestPartsExt;
use axum::{http::request::Parts, response::IntoResponse};
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::{Authorization, Cookie};
use axum_extra::TypedHeader;
use jsonwebtoken::errors::ErrorKind;
use serde::de::DeserializeOwned;

use crate::Decoder;

/// A generic struct for holding the claims of a JWT token.
///
/// The type parameter `E` specifies the token extraction strategy.
/// By default, it uses `BearerTokenExtractor` to extract tokens from
/// the `Authorization: Bearer <token>` header.
///
/// # Examples
///
/// ```ignore
/// // Default: Bearer token extraction
/// async fn handler(user: Claims<MyClaims>) -> Response {
///     Json(user.claims).into_response()
/// }
///
/// // Custom header extraction
/// struct XAuthToken;
/// impl ExtractorConfig for XAuthToken {
///     fn value() -> &'static str { "x-auth-token" }
/// }
/// async fn handler(user: Claims<MyClaims, HeaderTokenExtractor<XAuthToken>>) -> Response {
///     Json(user.claims).into_response()
/// }
///
/// // Cookie extraction
/// struct AuthCookie;
/// impl ExtractorConfig for AuthCookie {
///     fn value() -> &'static str { "auth_token" }
/// }
/// async fn handler(user: Claims<MyClaims, CookieTokenExtractor<AuthCookie>>) -> Response {
///     Json(user.claims).into_response()
/// }
/// ```
#[derive(Debug)]
pub struct Claims<T, E = BearerTokenExtractor> {
    /// The JWT claims payload
    pub claims: T,
    _extractor: PhantomData<E>,
}

/// Trait for extracting tokens from request parts
#[async_trait]
pub trait TokenExtractor {
    async fn extract_token(parts: &mut Parts) -> Result<String, AuthError>;
}

/// Extracts JWT tokens from the `Authorization: Bearer <token>` header.
///
/// This is the default token extractor.
pub struct BearerTokenExtractor;

#[async_trait]
impl TokenExtractor for BearerTokenExtractor {
    async fn extract_token(parts: &mut Parts) -> Result<String, AuthError> {
        let auth: TypedHeader<Authorization<Bearer>> =
            parts.extract().await.map_err(|_| AuthError::MissingToken)?;

        Ok(auth.token().to_string())
    }
}

/// Trait for providing configuration to token extractors.
///
/// This trait allows users to define custom header names, cookie names, or query parameters
/// for token extraction.
pub trait ExtractorConfig {
    /// Returns the configuration value (header name, cookie name, or query parameter name)
    fn value() -> &'static str;
}

/// Creates a custom header token extractor with the given name and header value.
///
/// # Examples
///
/// ```
/// use axum_jwt_auth::define_header_extractor;
///
/// // Define a custom header extractor for "x-auth-token"
/// define_header_extractor!(XAuthToken, "x-auth-token");
///
/// // Now use it in your handlers:
/// // async fn handler(user: Claims<MyClaims, HeaderTokenExtractor<XAuthToken>>) -> Response { ... }
/// ```
#[macro_export]
macro_rules! define_header_extractor {
    ($name:ident, $header:expr) => {
        pub struct $name;
        impl $crate::ExtractorConfig for $name {
            fn value() -> &'static str {
                $header
            }
        }
    };
}

/// Creates a custom cookie token extractor with the given name and cookie value.
///
/// # Examples
///
/// ```
/// use axum_jwt_auth::define_cookie_extractor;
///
/// // Define a custom cookie extractor for "auth_token"
/// define_cookie_extractor!(AuthTokenCookie, "auth_token");
///
/// // Now use it in your handlers:
/// // async fn handler(user: Claims<MyClaims, CookieTokenExtractor<AuthTokenCookie>>) -> Response { ... }
/// ```
#[macro_export]
macro_rules! define_cookie_extractor {
    ($name:ident, $cookie:expr) => {
        pub struct $name;
        impl $crate::ExtractorConfig for $name {
            fn value() -> &'static str {
                $cookie
            }
        }
    };
}

/// Creates a custom query parameter token extractor with the given name and parameter value.
///
/// # Examples
///
/// ```
/// use axum_jwt_auth::define_query_extractor;
///
/// // Define a custom query extractor for "token"
/// define_query_extractor!(TokenParam, "token");
///
/// // Now use it in your handlers:
/// // async fn handler(user: Claims<MyClaims, QueryTokenExtractor<TokenParam>>) -> Response { ... }
/// ```
#[macro_export]
macro_rules! define_query_extractor {
    ($name:ident, $param:expr) => {
        pub struct $name;
        impl $crate::ExtractorConfig for $name {
            fn value() -> &'static str {
                $param
            }
        }
    };
}

/// Extracts JWT tokens from a custom HTTP header.
///
/// # Examples
///
/// ```ignore
/// // Define a configuration for the header name
/// struct XAuthToken;
/// impl ExtractorConfig for XAuthToken {
///     fn value() -> &'static str { "x-auth-token" }
/// }
///
/// // Use it in your handler
/// async fn handler(Claims(claims): Claims<MyClaims, HeaderTokenExtractor<XAuthToken>>) -> Response {
///     // ...
/// }
/// ```
pub struct HeaderTokenExtractor<C: ExtractorConfig>(PhantomData<C>);

#[async_trait]
impl<C: ExtractorConfig> TokenExtractor for HeaderTokenExtractor<C> {
    async fn extract_token(parts: &mut Parts) -> Result<String, AuthError> {
        let header_name = HeaderName::from_static(C::value());

        parts
            .headers
            .get(&header_name)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
            .ok_or(AuthError::MissingToken)
    }
}

/// Extracts JWT tokens from a cookie.
///
/// # Examples
///
/// ```ignore
/// // Define a configuration for the cookie name
/// struct AuthTokenCookie;
/// impl ExtractorConfig for AuthTokenCookie {
///     fn value() -> &'static str { "auth_token" }
/// }
///
/// // Use it in your handler
/// async fn handler(Claims(claims): Claims<MyClaims, CookieTokenExtractor<AuthTokenCookie>>) -> Response {
///     // ...
/// }
/// ```
pub struct CookieTokenExtractor<C: ExtractorConfig>(PhantomData<C>);

#[async_trait]
impl<C: ExtractorConfig> TokenExtractor for CookieTokenExtractor<C> {
    async fn extract_token(parts: &mut Parts) -> Result<String, AuthError> {
        let cookies: TypedHeader<Cookie> =
            parts.extract().await.map_err(|_| AuthError::MissingToken)?;

        cookies
            .get(C::value())
            .map(|s| s.to_string())
            .ok_or(AuthError::MissingToken)
    }
}

/// Extracts JWT tokens from a query parameter.
///
/// # Examples
///
/// ```ignore
/// // Define a configuration for the query parameter name
/// struct TokenParam;
/// impl ExtractorConfig for TokenParam {
///     fn value() -> &'static str { "token" }
/// }
///
/// // Use it in your handler
/// async fn handler(Claims(claims): Claims<MyClaims, QueryTokenExtractor<TokenParam>>) -> Response {
///     // ...
/// }
/// ```
pub struct QueryTokenExtractor<C: ExtractorConfig>(PhantomData<C>);

#[async_trait]
impl<C: ExtractorConfig> TokenExtractor for QueryTokenExtractor<C> {
    async fn extract_token(parts: &mut Parts) -> Result<String, AuthError> {
        let query_string = parts.uri.query().ok_or(AuthError::MissingToken)?;

        // Parse query parameters manually
        for pair in query_string.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                if key == C::value() {
                    return Ok(value.to_string());
                }
            }
        }

        Err(AuthError::MissingToken)
    }
}

impl<S, T, E> axum::extract::FromRequestParts<S> for Claims<T, E>
where
    JwtDecoderState<T>: FromRef<S>,
    S: Send + Sync,
    T: DeserializeOwned,
    E: TokenExtractor,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let token = E::extract_token(parts).await?;

        let state = JwtDecoderState::from_ref(state);
        let token_data = state
            .decoder
            .clone()
            .decode(&token)
            .await
            .map_err(map_jwt_error)?;

        Ok(Claims {
            claims: token_data.claims,
            _extractor: PhantomData,
        })
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

    // ============================================================================
    // Macro Tests
    // ============================================================================

    #[test]
    fn test_header_extractor_macro() {
        define_header_extractor!(TestHeader, "x-test-header");
        assert_eq!(TestHeader::value(), "x-test-header");
    }

    #[test]
    fn test_cookie_extractor_macro() {
        define_cookie_extractor!(TestCookie, "test_cookie");
        assert_eq!(TestCookie::value(), "test_cookie");
    }

    #[test]
    fn test_query_extractor_macro() {
        define_query_extractor!(TestQuery, "test_param");
        assert_eq!(TestQuery::value(), "test_param");
    }

    // ============================================================================
    // Error Mapping Tests
    // ============================================================================

    #[tokio::test]
    async fn test_map_jwt_error_expired_signature() {
        use jsonwebtoken::errors::Error as JwtError;

        let jwt_error = JwtError::from(ErrorKind::ExpiredSignature);
        let auth_error = map_jwt_error(crate::Error::Jwt(jwt_error));
        assert_eq!(auth_error, AuthError::ExpiredSignature);
    }

    #[tokio::test]
    async fn test_map_jwt_error_invalid_signature() {
        use jsonwebtoken::errors::Error as JwtError;

        let jwt_error = JwtError::from(ErrorKind::InvalidSignature);
        let auth_error = map_jwt_error(crate::Error::Jwt(jwt_error));
        assert_eq!(auth_error, AuthError::InvalidSignature);
    }

    #[tokio::test]
    async fn test_map_jwt_error_invalid_audience() {
        use jsonwebtoken::errors::Error as JwtError;

        let jwt_error = JwtError::from(ErrorKind::InvalidAudience);
        let auth_error = map_jwt_error(crate::Error::Jwt(jwt_error));
        assert_eq!(auth_error, AuthError::InvalidAudience);
    }

    #[tokio::test]
    async fn test_map_jwt_error_invalid_algorithm() {
        use jsonwebtoken::errors::Error as JwtError;

        let jwt_error = JwtError::from(ErrorKind::InvalidAlgorithm);
        let auth_error = map_jwt_error(crate::Error::Jwt(jwt_error));
        assert_eq!(auth_error, AuthError::InvalidAlgorithm);
    }

    #[tokio::test]
    async fn test_map_jwt_error_invalid_token() {
        use jsonwebtoken::errors::Error as JwtError;

        let jwt_error = JwtError::from(ErrorKind::InvalidToken);
        let auth_error = map_jwt_error(crate::Error::Jwt(jwt_error));
        assert_eq!(auth_error, AuthError::InvalidToken);
    }

    #[tokio::test]
    async fn test_map_jwt_error_invalid_issuer() {
        use jsonwebtoken::errors::Error as JwtError;

        let jwt_error = JwtError::from(ErrorKind::InvalidIssuer);
        let auth_error = map_jwt_error(crate::Error::Jwt(jwt_error));
        assert_eq!(auth_error, AuthError::InvalidIssuer);
    }

    #[tokio::test]
    async fn test_map_jwt_error_invalid_subject() {
        use jsonwebtoken::errors::Error as JwtError;

        let jwt_error = JwtError::from(ErrorKind::InvalidSubject);
        let auth_error = map_jwt_error(crate::Error::Jwt(jwt_error));
        assert_eq!(auth_error, AuthError::InvalidSubject);
    }

    #[tokio::test]
    async fn test_map_jwt_error_immature_signature() {
        use jsonwebtoken::errors::Error as JwtError;

        let jwt_error = JwtError::from(ErrorKind::ImmatureSignature);
        let auth_error = map_jwt_error(crate::Error::Jwt(jwt_error));
        assert_eq!(auth_error, AuthError::ImmatureSignature);
    }

    #[tokio::test]
    async fn test_map_jwt_error_missing_algorithm() {
        use jsonwebtoken::errors::Error as JwtError;

        let jwt_error = JwtError::from(ErrorKind::MissingAlgorithm);
        let auth_error = map_jwt_error(crate::Error::Jwt(jwt_error));
        assert_eq!(auth_error, AuthError::MissingAlgorithm);
    }

    #[tokio::test]
    async fn test_map_jwt_error_missing_required_claim() {
        use jsonwebtoken::errors::Error as JwtError;

        let jwt_error = JwtError::from(ErrorKind::MissingRequiredClaim("sub".to_string()));
        let auth_error = map_jwt_error(crate::Error::Jwt(jwt_error));
        assert_eq!(
            auth_error,
            AuthError::MissingRequiredClaim("sub".to_string())
        );
    }

    #[tokio::test]
    async fn test_map_jwt_error_non_jwt_error() {
        let error = crate::Error::KeyNotFound(Some("test_kid".to_string()));
        let auth_error = map_jwt_error(error);
        assert_eq!(auth_error, AuthError::InternalError);
    }

    // ============================================================================
    // BearerTokenExtractor Tests
    // ============================================================================

    #[tokio::test]
    async fn test_bearer_token_extractor_valid() {
        let req = Request::builder()
            .header("Authorization", "Bearer test_token")
            .body(Body::empty())
            .unwrap();

        let token = BearerTokenExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_ok());
        assert_eq!(token.unwrap(), "test_token");
    }

    #[tokio::test]
    async fn test_bearer_token_extractor_valid_long_token() {
        let long_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let req = Request::builder()
            .header("Authorization", format!("Bearer {}", long_token))
            .body(Body::empty())
            .unwrap();

        let token = BearerTokenExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_ok());
        assert_eq!(token.unwrap(), long_token);
    }

    #[tokio::test]
    async fn test_bearer_token_extractor_invalid_scheme() {
        let req = Request::builder()
            .header("Authorization", "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .unwrap();

        let token = BearerTokenExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_err());
        assert_eq!(token.unwrap_err(), AuthError::MissingToken);
    }

    #[tokio::test]
    async fn test_bearer_token_extractor_malformed_header() {
        let req = Request::builder()
            .header("Authorization", "BearerMissingSpace")
            .body(Body::empty())
            .unwrap();

        let token = BearerTokenExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_err());
        assert_eq!(token.unwrap_err(), AuthError::MissingToken);
    }

    #[tokio::test]
    async fn test_bearer_token_extractor_missing_header() {
        let req = Request::builder().body(Body::empty()).unwrap();
        let token = BearerTokenExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_err());
        assert_eq!(token.unwrap_err(), AuthError::MissingToken);
    }

    #[tokio::test]
    async fn test_bearer_token_extractor_empty_token() {
        let req = Request::builder()
            .header("Authorization", "Bearer ")
            .body(Body::empty())
            .unwrap();

        let token = BearerTokenExtractor::extract_token(&mut req.into_parts().0).await;
        // This should succeed as the Bearer scheme is valid, even if the token is empty
        assert!(token.is_ok());
        assert_eq!(token.unwrap(), "");
    }

    #[tokio::test]
    async fn test_bearer_token_extractor_case_sensitivity() {
        // Bearer scheme should be case-insensitive according to HTTP spec
        let req = Request::builder()
            .header("Authorization", "bearer test_token")
            .body(Body::empty())
            .unwrap();

        let token = BearerTokenExtractor::extract_token(&mut req.into_parts().0).await;
        // axum-extra's Bearer implementation is case-insensitive
        assert!(token.is_ok());
        assert_eq!(token.unwrap(), "test_token");
    }

    // ============================================================================
    // HeaderTokenExtractor Tests
    // ============================================================================

    #[tokio::test]
    async fn test_header_token_extractor_valid() {
        define_header_extractor!(XAuthToken, "x-auth-token");
        type XAuthTokenExtractor = HeaderTokenExtractor<XAuthToken>;

        let req = Request::builder()
            .header("x-auth-token", "test_token_123")
            .body(Body::empty())
            .unwrap();

        let token = XAuthTokenExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_ok());
        assert_eq!(token.unwrap(), "test_token_123");
    }

    #[tokio::test]
    async fn test_header_token_extractor_missing_header() {
        define_header_extractor!(XAuthToken2, "x-auth-token");
        type XAuthTokenExtractor = HeaderTokenExtractor<XAuthToken2>;

        let req = Request::builder().body(Body::empty()).unwrap();
        let token = XAuthTokenExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_err());
        assert_eq!(token.unwrap_err(), AuthError::MissingToken);
    }

    #[tokio::test]
    async fn test_header_token_extractor_empty_value() {
        define_header_extractor!(XAuthToken3, "x-auth-token");
        type XAuthTokenExtractor = HeaderTokenExtractor<XAuthToken3>;

        let req = Request::builder()
            .header("x-auth-token", "")
            .body(Body::empty())
            .unwrap();

        let token = XAuthTokenExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_ok());
        assert_eq!(token.unwrap(), "");
    }

    #[tokio::test]
    async fn test_header_token_extractor_special_characters() {
        define_header_extractor!(XAuthToken4, "x-auth-token");
        type XAuthTokenExtractor = HeaderTokenExtractor<XAuthToken4>;

        let req = Request::builder()
            .header("x-auth-token", "token-with-special.chars_123")
            .body(Body::empty())
            .unwrap();

        let token = XAuthTokenExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_ok());
        assert_eq!(token.unwrap(), "token-with-special.chars_123");
    }

    #[tokio::test]
    async fn test_header_token_extractor_different_header_names() {
        define_header_extractor!(ApiKey, "x-api-key");
        type ApiKeyExtractor = HeaderTokenExtractor<ApiKey>;

        let req = Request::builder()
            .header("x-api-key", "api_key_value")
            .header("x-auth-token", "auth_token_value")
            .body(Body::empty())
            .unwrap();

        let token = ApiKeyExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_ok());
        assert_eq!(token.unwrap(), "api_key_value");
    }

    // ============================================================================
    // CookieTokenExtractor Tests
    // ============================================================================

    #[tokio::test]
    async fn test_cookie_token_extractor_valid() {
        define_cookie_extractor!(AuthTokenCookie, "auth_token");
        type AuthCookieExtractor = CookieTokenExtractor<AuthTokenCookie>;

        let req = Request::builder()
            .header("Cookie", "auth_token=my_jwt_token; other=value")
            .body(Body::empty())
            .unwrap();

        let token = AuthCookieExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_ok());
        assert_eq!(token.unwrap(), "my_jwt_token");
    }

    #[tokio::test]
    async fn test_cookie_token_extractor_single_cookie() {
        define_cookie_extractor!(AuthTokenCookie2, "auth_token");
        type AuthCookieExtractor = CookieTokenExtractor<AuthTokenCookie2>;

        let req = Request::builder()
            .header("Cookie", "auth_token=my_jwt_token")
            .body(Body::empty())
            .unwrap();

        let token = AuthCookieExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_ok());
        assert_eq!(token.unwrap(), "my_jwt_token");
    }

    #[tokio::test]
    async fn test_cookie_token_extractor_missing_cookie() {
        define_cookie_extractor!(AuthTokenCookie3, "auth_token");
        type AuthCookieExtractor = CookieTokenExtractor<AuthTokenCookie3>;

        let req = Request::builder()
            .header("Cookie", "other=value")
            .body(Body::empty())
            .unwrap();
        let token = AuthCookieExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_err());
        assert_eq!(token.unwrap_err(), AuthError::MissingToken);
    }

    #[tokio::test]
    async fn test_cookie_token_extractor_no_cookies() {
        define_cookie_extractor!(AuthTokenCookie4, "auth_token");
        type AuthCookieExtractor = CookieTokenExtractor<AuthTokenCookie4>;

        let req = Request::builder().body(Body::empty()).unwrap();
        let token = AuthCookieExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_err());
        assert_eq!(token.unwrap_err(), AuthError::MissingToken);
    }

    #[tokio::test]
    async fn test_cookie_token_extractor_multiple_cookies() {
        define_cookie_extractor!(AuthTokenCookie5, "auth_token");
        type AuthCookieExtractor = CookieTokenExtractor<AuthTokenCookie5>;

        let req = Request::builder()
            .header("Cookie", "session=abc123; auth_token=my_jwt; user_id=456")
            .body(Body::empty())
            .unwrap();

        let token = AuthCookieExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_ok());
        assert_eq!(token.unwrap(), "my_jwt");
    }

    #[tokio::test]
    async fn test_cookie_token_extractor_empty_value() {
        define_cookie_extractor!(AuthTokenCookie6, "auth_token");
        type AuthCookieExtractor = CookieTokenExtractor<AuthTokenCookie6>;

        let req = Request::builder()
            .header("Cookie", "auth_token=")
            .body(Body::empty())
            .unwrap();

        let token = AuthCookieExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_ok());
        assert_eq!(token.unwrap(), "");
    }

    #[tokio::test]
    async fn test_cookie_token_extractor_with_spaces() {
        define_cookie_extractor!(AuthTokenCookie7, "auth_token");
        type AuthCookieExtractor = CookieTokenExtractor<AuthTokenCookie7>;

        let req = Request::builder()
            .header("Cookie", "auth_token=my_jwt_token;  other=value")
            .body(Body::empty())
            .unwrap();

        let token = AuthCookieExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_ok());
        assert_eq!(token.unwrap(), "my_jwt_token");
    }

    // ============================================================================
    // QueryTokenExtractor Tests
    // ============================================================================

    #[tokio::test]
    async fn test_query_token_extractor_valid() {
        define_query_extractor!(TokenParam, "token");
        type TokenParamExtractor = QueryTokenExtractor<TokenParam>;

        let req = Request::builder()
            .uri("http://example.com/api?token=my_jwt_token&other=value")
            .body(Body::empty())
            .unwrap();

        let token = TokenParamExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_ok());
        assert_eq!(token.unwrap(), "my_jwt_token");
    }

    #[tokio::test]
    async fn test_query_token_extractor_single_param() {
        define_query_extractor!(TokenParam2, "token");
        type TokenParamExtractor = QueryTokenExtractor<TokenParam2>;

        let req = Request::builder()
            .uri("http://example.com/api?token=my_jwt_token")
            .body(Body::empty())
            .unwrap();

        let token = TokenParamExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_ok());
        assert_eq!(token.unwrap(), "my_jwt_token");
    }

    #[tokio::test]
    async fn test_query_token_extractor_missing_parameter() {
        define_query_extractor!(TokenParam3, "token");
        type TokenParamExtractor = QueryTokenExtractor<TokenParam3>;

        let req = Request::builder()
            .uri("http://example.com/api?other=value")
            .body(Body::empty())
            .unwrap();
        let token = TokenParamExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_err());
        assert_eq!(token.unwrap_err(), AuthError::MissingToken);
    }

    #[tokio::test]
    async fn test_query_token_extractor_no_query_string() {
        define_query_extractor!(TokenParam4, "token");
        type TokenParamExtractor = QueryTokenExtractor<TokenParam4>;

        let req = Request::builder()
            .uri("http://example.com/api")
            .body(Body::empty())
            .unwrap();
        let token = TokenParamExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_err());
        assert_eq!(token.unwrap_err(), AuthError::MissingToken);
    }

    #[tokio::test]
    async fn test_query_token_extractor_empty_value() {
        define_query_extractor!(TokenParam5, "token");
        type TokenParamExtractor = QueryTokenExtractor<TokenParam5>;

        let req = Request::builder()
            .uri("http://example.com/api?token=")
            .body(Body::empty())
            .unwrap();

        let token = TokenParamExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_ok());
        assert_eq!(token.unwrap(), "");
    }

    #[tokio::test]
    async fn test_query_token_extractor_multiple_params() {
        define_query_extractor!(TokenParam6, "token");
        type TokenParamExtractor = QueryTokenExtractor<TokenParam6>;

        let req = Request::builder()
            .uri("http://example.com/api?user=john&token=my_jwt&format=json")
            .body(Body::empty())
            .unwrap();

        let token = TokenParamExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_ok());
        assert_eq!(token.unwrap(), "my_jwt");
    }

    #[tokio::test]
    async fn test_query_token_extractor_url_encoded() {
        define_query_extractor!(TokenParam7, "token");
        type TokenParamExtractor = QueryTokenExtractor<TokenParam7>;

        let req = Request::builder()
            .uri("http://example.com/api?token=value%2Bwith%2Bplus")
            .body(Body::empty())
            .unwrap();

        let token = TokenParamExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_ok());
        assert_eq!(token.unwrap(), "value%2Bwith%2Bplus");
    }

    #[tokio::test]
    async fn test_query_token_extractor_partial_match() {
        define_query_extractor!(TokenParam8, "token");
        type TokenParamExtractor = QueryTokenExtractor<TokenParam8>;

        // Should not match "refresh_token" when looking for "token"
        let req = Request::builder()
            .uri("http://example.com/api?refresh_token=my_jwt")
            .body(Body::empty())
            .unwrap();

        let token = TokenParamExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_err());
        assert_eq!(token.unwrap_err(), AuthError::MissingToken);
    }

    #[tokio::test]
    async fn test_query_token_extractor_first_occurrence() {
        define_query_extractor!(TokenParam9, "token");
        type TokenParamExtractor = QueryTokenExtractor<TokenParam9>;

        // If token appears multiple times, should get the first one
        let req = Request::builder()
            .uri("http://example.com/api?token=first&other=value&token=second")
            .body(Body::empty())
            .unwrap();

        let token = TokenParamExtractor::extract_token(&mut req.into_parts().0).await;
        assert!(token.is_ok());
        assert_eq!(token.unwrap(), "first");
    }

    // ============================================================================
    // AuthError IntoResponse Tests
    // ============================================================================

    #[tokio::test]
    async fn test_auth_error_invalid_token_response() {
        let response = AuthError::InvalidToken.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_error_expired_signature_response() {
        let response = AuthError::ExpiredSignature.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_error_internal_error_response() {
        let response = AuthError::InternalError.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_auth_error_missing_token_response() {
        let response = AuthError::MissingToken.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_error_missing_required_claim_response() {
        let response = AuthError::MissingRequiredClaim("sub".to_string()).into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
