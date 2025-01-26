use std::sync::Arc;

use dashmap::DashMap;
use derive_builder::Builder;
use jsonwebtoken::{jwk::JwkSet, DecodingKey, TokenData, Validation};
use serde::de::DeserializeOwned;

use crate::{Error, JwtDecoder};

const DEFAULT_CACHE_DURATION: std::time::Duration = std::time::Duration::from_secs(60 * 60); // 1 hour
const DEFAULT_RETRY_COUNT: usize = 3; // 3 attempts
const DEFAULT_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1); // 1 second

#[derive(Debug, Clone, Builder)]
pub struct RemoteJwksDecoderConfig {
    pub cache_duration: std::time::Duration,
    pub retry_count: usize,
    pub backoff: std::time::Duration,
}

impl Default for RemoteJwksDecoderConfig {
    fn default() -> Self {
        Self {
            cache_duration: DEFAULT_CACHE_DURATION,
            retry_count: DEFAULT_RETRY_COUNT,
            backoff: DEFAULT_BACKOFF,
        }
    }
}

/// Remote JWKS decoder.
/// It fetches the JWKS from the given URL and caches it for the given duration.
/// It uses the cached JWKS to decode the JWT tokens.
#[derive(Clone, Builder)]
pub struct RemoteJwksDecoder {
    jwks_url: String,
    config: RemoteJwksDecoderConfig,
    keys_cache: Arc<DashMap<String, DecodingKey>>,
    validation: Validation,
    client: reqwest::Client,
}

impl RemoteJwksDecoder {
    pub fn new(jwks_url: String) -> Self {
        RemoteJwksDecoderBuilder::default()
            .jwks_url(jwks_url)
            .build()
            .unwrap()
    }

    async fn refresh_keys(&self) -> Result<(), Error> {
        let max_attempts = self.config.retry_count;
        let mut attempt = 0;
        let mut err = None;

        while attempt < max_attempts {
            match self.refresh_keys_once().await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    err = Some(e);
                    attempt += 1;
                    tokio::time::sleep(self.config.backoff).await;
                }
            }
        }

        // Last attempt failed, return the error
        Err(err.unwrap())
    }

    async fn refresh_keys_once(&self) -> Result<(), Error> {
        let jwks = self
            .client
            .get(&self.jwks_url)
            .send()
            .await?
            .json::<JwkSet>()
            .await?;

        self.keys_cache.clear();
        for jwk in jwks.keys.iter() {
            let key_id = jwk.common.key_id.to_owned();
            let key = DecodingKey::from_jwk(jwk).map_err(Error::Jwt)?;
            self.keys_cache.insert(key_id.unwrap_or_default(), key);
        }

        Ok(())
    }

    /// Refreshes the JWKS cache periodically.
    /// It runs in a loop and never returns, so it should be run in a separate tokio task
    /// using [`tokio::spawn`]. If the JWKS refresh fails after multiple attemps,
    /// it logs the error and continues. The decoder will use the stale keys until the next refresh
    /// succeeds or the universe ends, whichever comes first.
    pub async fn refresh_keys_periodically(&self) {
        loop {
            tracing::info!("Refreshing JWKS");
            match self.refresh_keys().await {
                Ok(_) => {}
                Err(err) => {
                    // log the error and continue with stale keys
                    tracing::error!(
                        "Failed to refresh JWKS after {} attempts: {:?}",
                        self.config.retry_count,
                        err
                    );
                }
            }
            tokio::time::sleep(self.config.cache_duration).await;
        }
    }
}

impl<T> JwtDecoder<T> for RemoteJwksDecoder
where
    T: for<'de> DeserializeOwned,
{
    fn decode(&self, token: &str) -> Result<TokenData<T>, Error> {
        let header = jsonwebtoken::decode_header(token)?;
        let target_kid = header.kid;
        if let Some(kid) = target_kid {
            // Try to find the key in the cache by kid
            if let Some(key) = self.keys_cache.get(&kid) {
                return Ok(jsonwebtoken::decode::<T>(
                    token,
                    key.value(),
                    &self.validation,
                )?);
            }
            return Err(Error::KeyNotFound(Some(kid)));
        }

        // Otherwise, try all the keys in the cache, returning the first one that works
        // If none of them work, return the error from the last one
        for key in self.keys_cache.iter() {
            match jsonwebtoken::decode::<T>(token, key.value(), &self.validation) {
                Ok(token_data) => return Ok(token_data),
                Err(e) => {
                    tracing::debug!("Failed to decode token with key {}: {:?}", key.key(), e);
                }
            }
        }
        Err(Error::KeyNotFound(target_kid))
    }
}
