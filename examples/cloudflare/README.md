# Cloudflare Access Example

Cloudflare Access delivers JWTs via:
- `Cf-Access-Jwt-Assertion` header (API clients)
- `CF_Authorization` cookie (browsers)

This example shows how to validate both.

## Setup

Get your Cloudflare Access settings:
```bash
export CF_TEAM_DOMAIN="your-team.cloudflareaccess.com"
export CF_AUD="your-application-aud-tag"
```

Run the example:
```bash
cargo run --example cloudflare
```

## Testing

Extract a token from a logged-in browser session (DevTools → Application → Cookies), then:

```bash
# Via header
curl -H "Cf-Access-Jwt-Assertion: eyJhbGc..." \
     http://localhost:3000/api/header

# Via cookie
curl -H "Cookie: CF_Authorization=eyJhbGc..." \
     http://localhost:3000/api/cookie
```

## Key Code

Define extractors:
```rust
define_header_extractor!(CfAccessJwtHeader, "cf-access-jwt-assertion");
define_cookie_extractor!(CfAuthCookie, "CF_Authorization");
```

Use in handlers:
```rust
async fn header_route(
    user: Claims<CloudflareAccessClaims, HeaderTokenExtractor<CfAccessJwtHeader>>
) -> Json<CloudflareAccessClaims> {
    Json(user.claims)
}

async fn cookie_route(
    user: Claims<CloudflareAccessClaims, CookieTokenExtractor<CfAuthCookie>>
) -> Json<CloudflareAccessClaims> {
    Json(user.claims)
}
```

Configure JWKS validation:
```rust
let jwks_url = format!("https://{}/cdn-cgi/access/certs", team_domain);
let mut validation = Validation::new(Algorithm::RS256);
validation.set_audience(&[&audience]);
validation.set_issuer(&[&format!("https://{}", team_domain)]);

let decoder = RemoteJwksDecoder::builder()
    .jwks_url(jwks_url)
    .validation(validation)
    .build()?;
```

## Routes

- `GET /` - Public (no auth)
- `GET /api/header` - Header auth
- `GET /api/cookie` - Cookie auth
- `GET /api/user` - User info

## Docs

- [Cloudflare Access Docs](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/)
- [Validating JWTs](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)
