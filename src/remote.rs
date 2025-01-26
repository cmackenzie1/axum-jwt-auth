use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;
use derive_builder::Builder;
use jsonwebtoken::{jwk::JwkSet, DecodingKey, TokenData, Validation};
use serde::de::DeserializeOwned;
use tokio::sync::Notify;

use crate::{Error, JwtDecoder};

const DEFAULT_CACHE_DURATION: std::time::Duration = std::time::Duration::from_secs(60 * 60); // 1 hour
const DEFAULT_RETRY_COUNT: usize = 3; // 3 attempts
const DEFAULT_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1); // 1 second

#[derive(Debug, Clone, Builder)]
pub struct RemoteJwksDecoderConfig {
    /// How long to cache the JWKS keys for
    #[builder(default = "DEFAULT_CACHE_DURATION")]
    pub cache_duration: std::time::Duration,
    /// How many times to retry fetching the JWKS keys if it fails
    #[builder(default = "DEFAULT_RETRY_COUNT")]
    pub retry_count: usize,
    /// How long to wait before retrying fetching the JWKS keys
    #[builder(default = "DEFAULT_BACKOFF")]
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
    /// The URL to fetch the JWKS from
    jwks_url: String,
    /// The configuration for the decoder
    #[builder(default = "RemoteJwksDecoderConfig::default()")]
    config: RemoteJwksDecoderConfig,
    /// The cache for the JWKS keys
    #[builder(default = "Arc::new(DashMap::new())")]
    keys_cache: Arc<DashMap<String, DecodingKey>>,
    /// The validation settings for the JWT tokens
    validation: Validation,
    /// The HTTP client to use for fetching the JWKS
    #[builder(default = "reqwest::Client::new()")]
    client: reqwest::Client,
    /// The initialized flag
    #[builder(default = "Arc::new(Notify::new())")]
    initialized: Arc<Notify>,
}

impl RemoteJwksDecoder {
    /// Creates a new [`RemoteJwksDecoder`] with the given JWKS URL.
    pub fn new(jwks_url: String) -> Self {
        RemoteJwksDecoderBuilder::default()
            .jwks_url(jwks_url)
            .build()
            .unwrap()
    }

    /// Refreshes the JWKS cache.
    /// It retries the refresh up to [`RemoteJwksDecoderConfig::retry_count`] times,
    /// waiting [`RemoteJwksDecoderConfig::backoff`] seconds between attempts.
    /// If it fails after all attempts, it returns the error.
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

    /// Refreshes the JWKS cache once.
    /// It fetches the JWKS from the given URL and caches the keys.
    async fn refresh_keys_once(&self) -> Result<(), Error> {
        let jwks = self
            .client
            .get(&self.jwks_url)
            .send()
            .await?
            .json::<JwkSet>()
            .await?;

        // Parse all keys first before clearing cache
        let mut new_keys = Vec::new();
        for jwk in jwks.keys.iter() {
            let key_id = jwk.common.key_id.to_owned();
            let key = DecodingKey::from_jwk(jwk).map_err(Error::Jwt)?;
            new_keys.push((key_id.unwrap_or_default(), key));
        }

        // Only clear and update cache after all keys parsed successfully
        self.keys_cache.clear();
        for (kid, key) in new_keys {
            self.keys_cache.insert(kid, key);
        }

        // Notify waiters after the first successful fetch
        self.initialized.notify_waiters();

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

    /// Ensures keys are available before proceeding
    async fn ensure_initialized(&self) {
        self.initialized.notified().await;
    }
}

#[async_trait]
impl<T> JwtDecoder<T> for RemoteJwksDecoder
where
    T: for<'de> DeserializeOwned,
{
    async fn decode(&self, token: &str) -> Result<TokenData<T>, Error> {
        self.ensure_initialized().await;
        let header = jsonwebtoken::decode_header(token)?;
        let target_kid = header.kid;

        // Try matching key ID first if present
        if let Some(ref kid) = target_kid {
            if let Some(key) = self.keys_cache.get(kid) {
                return Ok(jsonwebtoken::decode::<T>(
                    token,
                    key.value(),
                    &self.validation,
                )?);
            }
        }

        // Try all keys as fallback
        let mut last_error = None;
        for key in self.keys_cache.iter() {
            match jsonwebtoken::decode::<T>(token, key.value(), &self.validation) {
                Ok(token_data) => return Ok(token_data),
                Err(e) => last_error = Some(e),
            }
        }

        // Return last error if we had one, otherwise KeyNotFound
        if let Some(e) = last_error {
            Err(Error::Jwt(e))
        } else {
            Err(Error::KeyNotFound(target_kid))
        }
    }
}
