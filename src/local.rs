use async_trait::async_trait;
use jsonwebtoken::{DecodingKey, TokenData, Validation};
use serde::de::DeserializeOwned;

use crate::{Error, JwtDecoder};

/// Local decoder
/// It uses the given JWKS to decode the JWT tokens.
#[derive(Clone)]
pub struct LocalDecoder {
    keys: Vec<DecodingKey>,
    validation: Validation,
}

impl LocalDecoder {
    pub fn new(keys: Vec<DecodingKey>, validation: Validation) -> Self {
        Self { keys, validation }
    }

    pub fn set_validation(&mut self, validation: Validation) {
        self.validation = validation;
    }
}

impl From<Vec<DecodingKey>> for LocalDecoder {
    fn from(keys: Vec<DecodingKey>) -> Self {
        Self::new(keys, Validation::default())
    }
}

impl From<DecodingKey> for LocalDecoder {
    fn from(key: DecodingKey) -> Self {
        Self::new(vec![key], Validation::default())
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
        let mut err: Option<Error> = None;
        for key in self.keys.iter() {
            match jsonwebtoken::decode::<T>(token, key, &self.validation) {
                Ok(token_data) => return Ok(token_data),
                Err(e) => err = Some(e.into()),
            }
        }

        Err(err.unwrap())
    }
}
