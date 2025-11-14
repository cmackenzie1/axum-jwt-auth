# axum-jwt-auth

[![Rust](https://github.com/cmackenzie1/axum-jwt-auth/actions/workflows/rust.yml/badge.svg)](https://github.com/cmackenzie1/axum-jwt-auth/actions/workflows/rust.yml)
[![Crates.io Version](https://img.shields.io/crates/v/axum-jwt-auth)](https://crates.io/crates/axum-jwt-auth)
[![docs.rs](https://img.shields.io/docsrs/axum-jwt-auth)](https://docs.rs/axum-jwt-auth)

JWT authentication middleware for Axum. Supports local keys and remote JWKS with automatic caching and refresh.

## Installation

```bash
cargo add axum-jwt-auth
```

## Quick Start

```rust
use axum::{routing::get, Router};
use axum_jwt_auth::{Claims, JwtDecoderState, LocalDecoder};
use jsonwebtoken::{DecodingKey, Algorithm, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize)]
struct MyClaims {
    sub: String,
    exp: usize,
}

async fn protected(user: Claims<MyClaims>) -> String {
    format!("Hello, {}!", user.claims.sub)
}

#[tokio::main]
async fn main() {
    let keys = vec![DecodingKey::from_secret(b"secret")];
    let decoder = LocalDecoder::builder()
        .keys(keys)
        .validation(Validation::new(Algorithm::HS256))
        .build()
        .unwrap();

    let state = JwtDecoderState {
        decoder: Arc::new(decoder),
    };

    let app = Router::new()
        .route("/protected", get(protected))
        .with_state(state);

    // Server will expect: Authorization: Bearer <jwt>
}
```

## Features

- **Local validation**: Validate JWTs with local RSA/HMAC keys
- **Remote JWKS**: Automatic fetching, caching, and refresh of remote JWKS endpoints
- **Flexible token extraction**: Bearer tokens (default), custom headers or cookies
- **Type-safe claims**: Strongly-typed claims via generic extractors
- **Axum integration**: Drop-in extractor for route handlers

## Custom Token Extractors

Extract tokens from custom headers or cookies:

```rust
use axum_jwt_auth::{define_header_extractor, define_cookie_extractor};

define_header_extractor!(XAuthToken, "x-auth-token");
define_cookie_extractor!(AuthCookie, "auth_token");

async fn header_auth(user: Claims<MyClaims, HeaderTokenExtractor<XAuthToken>>) { }
async fn cookie_auth(user: Claims<MyClaims, CookieTokenExtractor<AuthCookie>>) { }
```

## Examples

See the [examples](./examples/) directory for complete working examples:

- [**local**](./examples/local/) - Local RSA key validation
- [**remote**](./examples/remote/) - Remote JWKS with caching and retry logic
- [**cloudflare**](./examples/cloudflare/) - Cloudflare Access JWT validation

## License

MIT - see [LICENSE](LICENSE) for details.
