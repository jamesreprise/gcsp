use crate::metrics::consts::*;
use std::time::Instant;

use axum::{extract::Request, middleware::Next, response::Response};
use metrics::{counter, histogram};

use super::gcs;

pub(crate) async fn metrics(request: Request, next: Next) -> Response {
    let start = Instant::now();

    let (request_parts, request_body) = request.into_parts();
    let request_body_bytes = axum::body::to_bytes(request_body, gcs::REQUEST_SIZE_BYTES_UPPERBOUND)
        .await
        .unwrap();
    histogram!(HTTP_REQUEST_SIZE_BYTES).record(request_body_bytes.len() as f64);

    let request = Request::from_parts(request_parts, request_body_bytes.into());

    let response = next.run(request).await;

    let (response_parts, response_body) = response.into_parts();
    let response_body_bytes =
        axum::body::to_bytes(response_body, gcs::REQUEST_SIZE_BYTES_UPPERBOUND)
            .await
            .unwrap();

    histogram!(HTTP_RESPONSE_SIZE_BYTES).record(response_body_bytes.len() as f64);

    // This could be GCS or the proxy itself.
    if response_parts.status.is_server_error() {
        counter!(PROXY_HTTP_SERVER_ERROR).increment(1)
    }

    if response_parts.status.is_success() {
        counter!(HTTP_RESPONSE_SUCCESS).increment(1)
    } else {
        counter!(HTTP_RESPONSE_FAILURE).increment(1)
    }

    histogram!(HTTP_REQUEST_DURATION_SECS).record(start.elapsed().as_secs_f64());

    Response::from_parts(response_parts, response_body_bytes.into())
}
