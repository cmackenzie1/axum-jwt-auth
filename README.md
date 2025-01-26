# axum-jwt-auth

[![Rust](https://github.com/cmackenzie1/axum-jwt-auth/actions/workflows/rust.yml/badge.svg)](https://github.com/cmackenzie1/axum-jwt-auth/actions/workflows/rust.yml)
[![Crates.io Version](https://img.shields.io/crates/v/axum-jwt-auth)](https://crates.io/crates/axum-jwt-auth)
[![docs.rs](https://img.shields.io/docsrs/axum-jwt-auth)](https://docs.rs/axum-jwt-auth)

A Rust library providing JWT authentication middleware for Axum web applications. It supports both local and remote JWKS validation, handles token extraction and validation, and provides strongly-typed claims access in your request handlers. Built on top of jsonwebtoken, it offers a simple yet flexible API for securing your Axum routes with JWT authentication.

## Installation

```bash
cargo add axum-jwt-auth
```

## Usage

See [examples](./examples/) for how to use the library. It includes a local and remote example.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
