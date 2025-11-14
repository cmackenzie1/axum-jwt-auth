use async_trait::async_trait;
use derive_builder::Builder;
use jsonwebtoken::{DecodingKey, TokenData, Validation};
use serde::de::DeserializeOwned;

use crate::{Error, JwtDecoder};

/// JWT decoder that validates tokens using locally stored keys.
///
/// Supports multiple decoding keys and tries them sequentially until one succeeds.
/// Ideal for scenarios with key rotation or multiple valid signing keys.
///
/// # Example
///
/// ```ignore
/// use axum_jwt_auth::LocalDecoder;
/// use jsonwebtoken::{DecodingKey, Algorithm, Validation};
///
/// let keys = vec![DecodingKey::from_secret(b"secret")];
/// let mut validation = Validation::new(Algorithm::HS256);
/// validation.set_audience(&["my-app"]);
///
/// let decoder = LocalDecoder::builder()
///     .keys(keys)
///     .validation(validation)
///     .build()
///     .unwrap();
/// ```
#[derive(Clone, Builder)]
pub struct LocalDecoder {
    keys: Vec<DecodingKey>,
    validation: Validation,
}

impl LocalDecoder {
    /// Creates a new `LocalDecoder` with the specified keys and validation settings.
    ///
    /// # Errors
    ///
    /// Returns `Error::Configuration` if:
    /// - No decoding keys are provided
    /// - No validation algorithms are configured
    /// - No audience is specified in validation
    pub fn new(keys: Vec<DecodingKey>, validation: Validation) -> Result<Self, Error> {
        if keys.is_empty() {
            return Err(Error::Configuration("No decoding keys provided".into()));
        }

        if validation.algorithms.is_empty() {
            return Err(Error::Configuration(
                "Validation algorithm is required".into(),
            ));
        }

        if validation.aud.is_none() {
            return Err(Error::Configuration(
                "Validation audience is required".into(),
            ));
        }

        Ok(Self { keys, validation })
    }

    /// Creates a new `LocalDecoderBuilder` for configuring a decoder.
    pub fn builder() -> LocalDecoderBuilder {
        LocalDecoderBuilder::default()
    }
}

#[async_trait]
impl<T> JwtDecoder<T> for LocalDecoder
where
    T: for<'de> DeserializeOwned,
{
    async fn decode(&self, token: &str) -> Result<TokenData<T>, Error> {
        // Try to decode the token with each key in the cache
        // If none of them work, return the error from the last one
        let mut last_error: Option<Error> = None;
        for key in self.keys.iter() {
            match jsonwebtoken::decode::<T>(token, key, &self.validation) {
                Ok(token_data) => return Ok(token_data),
                Err(e) => {
                    tracing::error!("Error decoding token: {}", e);
                    last_error = Some(Error::Jwt(e));
                }
            }
        }

        Err(last_error.unwrap_or_else(|| Error::Configuration("No keys available".into())))
    }
}
