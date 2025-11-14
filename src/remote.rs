use std::sync::Arc;

use dashmap::DashMap;
use jsonwebtoken::{DecodingKey, TokenData, Validation, jwk::JwkSet};
use serde::de::DeserializeOwned;
use tokio_util::sync::CancellationToken;

use crate::{Error, JwtDecoder};

const DEFAULT_CACHE_DURATION: std::time::Duration = std::time::Duration::from_secs(60 * 60); // 1 hour
const DEFAULT_RETRY_COUNT: usize = 3; // 3 attempts
const DEFAULT_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1); // 1 second

/// Configuration for remote JWKS fetching and caching behavior.
#[derive(Debug, Clone)]
pub struct RemoteJwksDecoderConfig {
    /// Duration to cache JWKS keys before refreshing (default: 1 hour)
    pub cache_duration: std::time::Duration,
    /// Number of retry attempts when fetching JWKS fails (default: 3)
    pub retry_count: usize,
    /// Delay between retry attempts (default: 1 second)
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
        RemoteJwksDecoderConfigBuilder {
            cache_duration: None,
            retry_count: None,
            backoff: None,
        }
    }
}

/// Builder for `RemoteJwksDecoderConfig`.
pub struct RemoteJwksDecoderConfigBuilder {
    cache_duration: Option<std::time::Duration>,
    retry_count: Option<usize>,
    backoff: Option<std::time::Duration>,
}

impl RemoteJwksDecoderConfigBuilder {
    /// Sets the cache duration.
    pub fn cache_duration(mut self, cache_duration: std::time::Duration) -> Self {
        self.cache_duration = Some(cache_duration);
        self
    }

    /// Sets the retry count.
    pub fn retry_count(mut self, retry_count: usize) -> Self {
        self.retry_count = Some(retry_count);
        self
    }

    /// Sets the backoff duration.
    pub fn backoff(mut self, backoff: std::time::Duration) -> Self {
        self.backoff = Some(backoff);
        self
    }

    /// Builds the `RemoteJwksDecoderConfig` with defaults for unset fields.
    pub fn build(self) -> RemoteJwksDecoderConfig {
        RemoteJwksDecoderConfig {
            cache_duration: self.cache_duration.unwrap_or(DEFAULT_CACHE_DURATION),
            retry_count: self.retry_count.unwrap_or(DEFAULT_RETRY_COUNT),
            backoff: self.backoff.unwrap_or(DEFAULT_BACKOFF),
        }
    }
}

/// JWT decoder that fetches and caches keys from a remote JWKS endpoint.
///
/// Automatically fetches JWKS from the specified URL, caches keys by their `kid` (key ID),
/// and periodically refreshes them in the background. Includes retry logic for robustness.
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
/// // Initialize: fetch keys and start background refresh task
/// decoder.initialize().await.unwrap();
/// ```
#[derive(Clone)]
pub struct RemoteJwksDecoder {
    /// The JWKS endpoint URL
    jwks_url: String,
    /// Configuration for caching and retry behavior
    config: RemoteJwksDecoderConfig,
    /// Thread-safe cache mapping key IDs to decoding keys
    keys_cache: Arc<DashMap<String, DecodingKey>>,
    /// JWT validation settings
    validation: Validation,
    /// HTTP client for fetching JWKS
    client: reqwest::Client,
}

impl RemoteJwksDecoder {
    /// Creates a new `RemoteJwksDecoder` with the given JWKS URL and default settings.
    ///
    /// # Errors
    ///
    /// Returns `Error::Configuration` if the builder fails to construct the decoder.
    pub fn new(jwks_url: String) -> Result<Self, Error> {
        RemoteJwksDecoderBuilder::new().jwks_url(jwks_url).build()
    }

    /// Creates a new builder for configuring a remote JWKS decoder.
    pub fn builder() -> RemoteJwksDecoderBuilder {
        RemoteJwksDecoderBuilder::new()
    }

    /// Performs an initial fetch of JWKS keys and starts the background refresh task.
    ///
    /// This method should be called once after construction. It will:
    /// 1. Immediately fetch keys from the JWKS endpoint
    /// 2. Spawn a background task to periodically refresh keys
    ///
    /// Returns a `CancellationToken` that can be used to gracefully stop the background refresh task.
    ///
    /// # Errors
    ///
    /// Returns an error if the initial fetch fails after all retry attempts.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let decoder = RemoteJwksDecoder::builder()
    ///     .jwks_url("https://example.com/.well-known/jwks.json".to_string())
    ///     .validation(Validation::new(Algorithm::RS256))
    ///     .build()?;
    ///
    /// // Fetch keys and start background refresh
    /// let shutdown_token = decoder.initialize().await?;
    ///
    /// // Later, during application shutdown:
    /// shutdown_token.cancel();
    /// ```
    pub async fn initialize(&self) -> Result<CancellationToken, Error> {
        // Fetch keys immediately
        self.refresh_keys().await?;

        // Create cancellation token for graceful shutdown
        let shutdown_token = CancellationToken::new();

        // Spawn background refresh task
        let decoder_clone = self.clone();
        let token_clone = shutdown_token.clone();
        tokio::spawn(async move {
            decoder_clone.refresh_keys_periodically(token_clone).await;
        });

        Ok(shutdown_token)
    }

    /// Manually triggers a JWKS refresh with retry logic.
    ///
    /// Useful for forcing an update outside the normal refresh cycle.
    ///
    /// # Errors
    ///
    /// Returns an error if the refresh fails after all retry attempts.
    pub async fn refresh(&self) -> Result<(), Error> {
        self.refresh_keys().await
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

        Ok(())
    }

    /// Runs a loop that periodically refreshes the JWKS cache until cancelled.
    ///
    /// This method should be spawned in a background task using `tokio::spawn`.
    /// Refresh failures are logged, and the decoder continues using stale keys until the next
    /// successful refresh.
    ///
    /// The loop will exit gracefully when the `shutdown_token` is cancelled.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use tokio_util::sync::CancellationToken;
    ///
    /// let decoder = RemoteJwksDecoder::builder()
    ///     .jwks_url("https://example.com/.well-known/jwks.json".to_string())
    ///     .build()
    ///     .unwrap();
    ///
    /// let shutdown_token = CancellationToken::new();
    /// let decoder_clone = decoder.clone();
    /// let token_clone = shutdown_token.clone();
    ///
    /// tokio::spawn(async move {
    ///     decoder_clone.refresh_keys_periodically(token_clone).await;
    /// });
    ///
    /// // Later, to stop the refresh task:
    /// shutdown_token.cancel();
    /// ```
    pub async fn refresh_keys_periodically(&self, shutdown_token: CancellationToken) {
        loop {
            tokio::select! {
                _ = shutdown_token.cancelled() => {
                    tracing::info!("JWKS refresh task shutting down gracefully");
                    break;
                }
                _ = tokio::time::sleep(self.config.cache_duration) => {
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
                }
            }
        }
    }

    /// Checks that the key cache has been initialized.
    ///
    /// # Errors
    ///
    /// Returns `Error::Configuration` if the cache is empty, which indicates
    /// that `initialize()` was never called.
    fn check_initialized(&self) -> Result<(), Error> {
        if self.keys_cache.is_empty() {
            Err(Error::Configuration(
                "JWKS decoder not initialized: call initialize() after building the decoder".into(),
            ))
        } else {
            Ok(())
        }
    }
}

/// Builder for `RemoteJwksDecoder`.
pub struct RemoteJwksDecoderBuilder {
    jwks_url: Option<String>,
    config: Option<RemoteJwksDecoderConfig>,
    keys_cache: Option<Arc<DashMap<String, DecodingKey>>>,
    validation: Option<Validation>,
    client: Option<reqwest::Client>,
}

impl RemoteJwksDecoderBuilder {
    /// Creates a new `RemoteJwksDecoderBuilder`.
    pub fn new() -> Self {
        Self {
            jwks_url: None,
            config: None,
            keys_cache: None,
            validation: None,
            client: None,
        }
    }

    /// Sets the JWKS URL.
    pub fn jwks_url(mut self, jwks_url: String) -> Self {
        self.jwks_url = Some(jwks_url);
        self
    }

    /// Sets the configuration.
    pub fn config(mut self, config: RemoteJwksDecoderConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Sets the keys cache.
    pub fn keys_cache(mut self, keys_cache: Arc<DashMap<String, DecodingKey>>) -> Self {
        self.keys_cache = Some(keys_cache);
        self
    }

    /// Sets the validation settings.
    pub fn validation(mut self, validation: Validation) -> Self {
        self.validation = Some(validation);
        self
    }

    /// Sets the HTTP client.
    pub fn client(mut self, client: reqwest::Client) -> Self {
        self.client = Some(client);
        self
    }

    /// Builds the `RemoteJwksDecoder`.
    ///
    /// # Errors
    ///
    /// Returns `Error::Configuration` if required fields are missing.
    pub fn build(self) -> Result<RemoteJwksDecoder, Error> {
        let jwks_url = self
            .jwks_url
            .ok_or_else(|| Error::Configuration("jwks_url is required".into()))?;

        let validation = self
            .validation
            .ok_or_else(|| Error::Configuration("validation is required".into()))?;

        // Configure client with sensible timeouts if not provided
        let client = self.client.unwrap_or_else(|| {
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .connect_timeout(std::time::Duration::from_secs(5))
                .build()
                .expect("Failed to build HTTP client")
        });

        Ok(RemoteJwksDecoder {
            jwks_url,
            config: self.config.unwrap_or_default(),
            keys_cache: self.keys_cache.unwrap_or_else(|| Arc::new(DashMap::new())),
            validation,
            client,
        })
    }
}

impl Default for RemoteJwksDecoderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> JwtDecoder<T> for RemoteJwksDecoder
where
    T: for<'de> DeserializeOwned,
{
    fn decode<'a>(
        &'a self,
        token: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<TokenData<T>, Error>> + Send + 'a>>
    {
        Box::pin(async move {
            self.check_initialized()?;
            let header = jsonwebtoken::decode_header(token)?;
            let target_kid = header.kid;

            if let Some(ref kid) = target_kid {
                if let Some(key) = self.keys_cache.get(kid) {
                    Ok(jsonwebtoken::decode::<T>(
                        token,
                        key.value(),
                        &self.validation,
                    )?)
                } else {
                    Err(Error::KeyNotFound(Some(kid.clone())))
                }
            } else {
                Err(Error::KeyNotFound(None))
            }
        })
    }
}
