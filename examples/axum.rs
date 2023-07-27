use std::sync::Arc;

use axum::{
    debug_handler,
    extract::FromRef,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};

use jwtrs::{Claims, JwtDecoderState, RemoteJwksDecoderBuilder};

#[derive(Clone, FromRef)]
struct AppState {
    decoder: JwtDecoderState,
}

async fn handler(claims: Claims) -> Response {
    format!("{:?}", claims).into_response()
}

#[tokio::main]
async fn main() {
    let state = AppState {
        decoder: JwtDecoderState {
            decoder: Arc::new(
                RemoteJwksDecoderBuilder::new(
                    "https://www.googleapis.com/oauth2/v3/certs".to_string(),
                )
                .build(),
            ),
        },
    };

    let app = Router::new().route("/", get(handler)).with_state(state);

    // run it with hyper on localhost:3000
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
