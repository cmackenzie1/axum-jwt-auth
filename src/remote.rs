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

/// Configuration for remote JWKS fetching and caching behavior.
#[derive(Debug, Clone, Builder)]
pub struct RemoteJwksDecoderConfig {
    /// Duration to cache JWKS keys before refreshing (default: 1 hour)
    #[builder(default = "DEFAULT_CACHE_DURATION")]
    pub cache_duration: std::time::Duration,
    /// Number of retry attempts when fetching JWKS fails (default: 3)
    #[builder(default = "DEFAULT_RETRY_COUNT")]
    pub retry_count: usize,
    /// Delay between retry attempts (default: 1 second)
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

impl RemoteJwksDecoderConfig {
    /// Creates a new builder for configuring JWKS fetching behavior.
    pub fn builder() -> RemoteJwksDecoderConfigBuilder {
        RemoteJwksDecoderConfigBuilder::default()
    }
}

/// JWT decoder that fetches and caches keys from a remote JWKS endpoint.
///
/// Automatically fetches JWKS from the specified URL, caches keys by their `kid` (key ID),
/// and periodically refreshes them. Includes retry logic for robustness.
///
/// # Example
///
/// ```ignore
/// use axum_jwt_auth::RemoteJwksDecoder;
/// use jsonwebtoken::{Algorithm, Validation};
///
/// let decoder = RemoteJwksDecoder::builder()
///     .jwks_url("https://example.com/.well-known/jwks.json".to_string())
///     .validation(Validation::new(Algorithm::RS256))
///     .build()
///     .unwrap();
///
/// // Spawn background refresh task
/// let decoder_clone = decoder.clone();
/// tokio::spawn(async move {
///     decoder_clone.refresh_keys_periodically().await;
/// });
/// ```
#[derive(Clone, Builder)]
pub struct RemoteJwksDecoder {
    /// The JWKS endpoint URL
    jwks_url: String,
    /// Configuration for caching and retry behavior
    #[builder(default = "RemoteJwksDecoderConfig::default()")]
    config: RemoteJwksDecoderConfig,
    /// Thread-safe cache mapping key IDs to decoding keys
    #[builder(default = "Arc::new(DashMap::new())")]
    keys_cache: Arc<DashMap<String, DecodingKey>>,
    /// JWT validation settings
    validation: Validation,
    /// HTTP client for fetching JWKS
    #[builder(default = "reqwest::Client::new()")]
    client: reqwest::Client,
    /// Notification for initialization completion
    #[builder(default = "Arc::new(Notify::new())")]
    initialized: Arc<Notify>,
}

impl RemoteJwksDecoder {
    /// Creates a new `RemoteJwksDecoder` with the given JWKS URL and default settings.
    ///
    /// # Errors
    ///
    /// Returns `Error::Configuration` if the builder fails to construct the decoder.
    pub fn new(jwks_url: String) -> Result<Self, Error> {
        RemoteJwksDecoderBuilder::default()
            .jwks_url(jwks_url)
            .build()
            .map_err(|e| Error::Configuration(e.to_string()))
    }

    /// Creates a new builder for configuring a remote JWKS decoder.
    pub fn builder() -> RemoteJwksDecoderBuilder {
        RemoteJwksDecoderBuilder::default()
    }

    /// Refreshes the JWKS cache with retry logic.
    ///
    /// Retries up to `config.retry_count` times, waiting `config.backoff` duration between attempts.
    ///
    /// # Errors
    ///
    /// Returns `Error::JwksRefresh` if all retry attempts fail.
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

        Err(Error::JwksRefresh {
            message: "Failed to refresh JWKS after multiple attempts".to_string(),
            retry_count: max_attempts,
            source: err.map(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
        })
    }

    /// Fetches JWKS from the remote URL and updates the cache.
    ///
    /// Parses all keys before updating the cache to ensure atomicity.
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

    /// Runs an infinite loop that periodically refreshes the JWKS cache.
    ///
    /// This method never returns and should be spawned in a background task using `tokio::spawn`.
    /// Refresh failures are logged, and the decoder continues using stale keys until the next
    /// successful refresh.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let decoder = RemoteJwksDecoder::builder()
    ///     .jwks_url("https://example.com/.well-known/jwks.json".to_string())
    ///     .build()
    ///     .unwrap();
    ///
    /// let decoder_clone = decoder.clone();
    /// tokio::spawn(async move {
    ///     decoder_clone.refresh_keys_periodically().await;
    /// });
    /// ```
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

    /// Ensures the key cache is initialized before attempting token validation.
    ///
    /// If the cache is empty, waits for the background refresh task to complete
    /// the first successful key fetch.
    async fn ensure_initialized(&self) {
        // If we already have keys, we're already initialized
        if !self.keys_cache.is_empty() {
            tracing::trace!("Key store already initialised, continuing.");
            return;
        }

        // If direct initialization failed, fall back to waiting for the background task
        tracing::trace!("Waiting for background initialization to complete");
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

        if let Some(ref kid) = target_kid {
            if let Some(key) = self.keys_cache.get(kid) {
                return Ok(jsonwebtoken::decode::<T>(
                    token,
                    key.value(),
                    &self.validation,
                )?);
            }
            return Err(Error::KeyNotFound(Some(kid.clone())));
        }
        return Err(Error::KeyNotFound(None));
    }
}
