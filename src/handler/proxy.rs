use super::aws_v4_auth_header::AWSV4AuthHeader;
use super::config::ProxyState;
use super::errors::ProxyError;
use super::gcp_signature::{self, GCPCredentials, GCPSignature, GCPSignatureRequest};
use super::gcs;
use crate::metrics::consts as crate_metrics;

use anyhow::Context;
use axum::{
    body::Body,
    extract::{Request, State},
    http::{self, HeaderMap, HeaderValue},
    response::IntoResponse,
};
use chrono::Utc;
use std::time::Instant;
use tracing::instrument;

// GCS's upper bound for multipart upload sizes.
// If you're hitting this: what's going on, big guy?
const FIVE_GIGABYTES_IN_BYTES: usize = 5 * 1024 * 1024 * 1024;

fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[instrument(skip_all, err, level = tracing::Level::DEBUG, fields(request_id=uuid()))]
pub async fn proxy(
    State(state): State<ProxyState>,
    client_request: Request<Body>,
) -> Result<impl IntoResponse, ProxyError> {
    let request_start = Instant::now();
    tracing::debug!(?client_request);

    let client_request_headers = client_request.headers().clone();
    let client_authorization_header = client_request_headers
        .get(http::header::AUTHORIZATION)
        .context("Couldn't get authorization header from client request")?
        .to_str()?;
    let aws_v4_auth_header = AWSV4AuthHeader::from_header(client_authorization_header)?;
    if aws_v4_auth_header.credential.hmac_access_key != state.config.hmac_access_key {
        return Err(anyhow::Error::msg(
            "AWS v4 authorisation header's access key was not equal to the supplied access key",
        )
        .into());
    }
    let proxy_request_region = aws_v4_auth_header.credential.region;
    let proxy_request_method = client_request.method().clone();
    let proxy_request_path = client_request.uri().path().to_string();
    let proxy_request_query = client_request.uri().query().unwrap_or("").to_string();
    let proxy_request_path_and_query = client_request
        .uri()
        .path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or("".to_string());
    let proxy_request_body = client_request.into_body();
    let proxy_request_body_bytes =
        axum::body::to_bytes(proxy_request_body, FIVE_GIGABYTES_IN_BYTES).await?;
    let proxy_request_body_bytes_length = proxy_request_body_bytes.len();

    let gcp_signature_request = GCPSignatureRequest {
        credentials: GCPCredentials {
            hmac_access_key: state.config.hmac_access_key,
            hmac_secret_key: state.config.hmac_secret_key,
        },
        csek_encryption_key: state.config.csek_encryption_key.clone(),
        region: proxy_request_region,
        method: proxy_request_method.clone(),
        path: proxy_request_path,
        query: proxy_request_query.clone(),
        datetime: Utc::now(),
        body: &proxy_request_body_bytes,
    };

    let GCPSignature {
        auth_header,
        goog_date,
        payload_hash,
    } = gcp_signature_request.sign()?;

    let mut proxy_request_headers = client_request_headers
        .into_iter()
        .filter_map(|(k, v)| {
            k.and_then(|key| {
                (!key.as_str().starts_with(gcs::AMZ_HEADER_KEY_PREFIX)).then_some((key, v))
            })
        })
        .collect::<HeaderMap>();

    proxy_request_headers.insert(http::header::HOST, HeaderValue::from_static(gcs::HOST));
    proxy_request_headers.insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(&auth_header)?,
    );
    proxy_request_headers.insert(gcs::DATE_HEADER_KEY, HeaderValue::from_str(&goog_date)?);
    proxy_request_headers.insert(
        gcs::CONTENT_SHA256_HEADER_KEY,
        HeaderValue::from_str(&payload_hash)?,
    );
    proxy_request_headers.insert(
        gcs::CSEK_ENCRYPTION_ALGORITHM_HEADER_KEY,
        HeaderValue::from_static(gcs::CSEK_ENCRYPTION_ALGORITHM),
    );
    proxy_request_headers.insert(
        gcs::CSEK_ENCRYPTION_KEY_HEADER_KEY,
        HeaderValue::from_str(&state.config.csek_encryption_key)?,
    );
    let csek_base64_of_sha256_of_encryption_key =
        gcp_signature::csek_base64_of_sha256(&state.config.csek_encryption_key)?;
    proxy_request_headers.insert(
        gcs::CSEK_ENCRYPTION_KEY_SHA256_HEADER_KEY,
        HeaderValue::from_str(&csek_base64_of_sha256_of_encryption_key)?,
    );

    tracing::debug!(?proxy_request_headers);

    let proxy_request_url = format!(
        "https://{host}:{port}{proxy_request_path_and_query}",
        host = gcs::HOST,
        port = gcs::PORT,
    );

    let reqwest_start = Instant::now();
    let server_response = state
        .http_client
        .request(proxy_request_method.clone(), proxy_request_url)
        .headers(proxy_request_headers)
        .body(proxy_request_body_bytes)
        .send()
        .await?;

    let reqwest_duration = reqwest_start.elapsed();
    metrics::histogram!(crate_metrics::GCS_REQUEST_DURATION_SECS)
        .record(reqwest_duration.as_secs_f64());

    let server_response_status = server_response.status();
    let server_response_headers = server_response.headers().clone();

    tracing::info!(
        %server_response_status,
        %proxy_request_method,
        proxy_request_path_and_query,
    );

    if proxy_request_body_bytes_length > 0 {
        let validation = validate_response(
            proxy_request_method,
            &proxy_request_query,
            &server_response_headers,
            &csek_base64_of_sha256_of_encryption_key,
        );
        if let Err(error) = validation {
            tracing::error!(?error, "Error validating server response.");
            // Crash to avoid sending out data if we suspect it is not being encrypted by GCS.
            panic!(
                "Couldn't validate server response. ENCRYPTION MAY NOT BE OCCURRING AS EXPECTED."
            );
        }
    };

    let server_response_body_stream = server_response.bytes_stream();
    let proxy_response_body_stream = axum::body::Body::from_stream(server_response_body_stream);

    let request_duration = request_start.elapsed();
    let processing_duration = request_duration - reqwest_duration;

    metrics::histogram!(crate_metrics::PROXY_PROCESSING_DURATION_SECS)
        .record(processing_duration.as_secs_f64());

    Ok((
        server_response_status,
        server_response_headers,
        proxy_response_body_stream,
    ))
}

#[instrument(skip_all, level = tracing::Level::DEBUG)]
fn validate_response(
    request_method: http::Method,
    request_query: &str,
    response_headers: &HeaderMap,
    csek_base64_of_sha256_of_encryption_key: &str,
) -> anyhow::Result<()> {
    match request_method {
        http::Method::GET => {
            validate_encryption_headers(response_headers, csek_base64_of_sha256_of_encryption_key)?;
        }
        http::Method::PUT => {
            validate_encryption_headers(response_headers, csek_base64_of_sha256_of_encryption_key)
                .or(validate_multipart_upload_part_query_and_headers(
                    request_query,
                    response_headers,
                )
                .then_some(())
                .ok_or(anyhow::Error::msg(
                    "Couldn't validate request as finishing a multi-part upload.",
                )))?;
        }
        http::Method::POST => {
            validate_encryption_headers(response_headers, csek_base64_of_sha256_of_encryption_key)
                .or(validate_multipart_upload_finish_headers(response_headers)
                    .then_some(())
                    .ok_or(anyhow::Error::msg(
                        "Couldn't validate request as finishing a multi-part upload.",
                    )))?;
        }
        _ => {
            anyhow::bail!("Unexpected HTTP method.");
        }
    };
    Ok(())
}

fn validate_encryption_headers(
    response_headers: &HeaderMap,
    csek_base64_of_sha256_of_encryption_key: &str,
) -> anyhow::Result<()> {
    match response_headers.get(gcs::CSEK_ENCRYPTION_ALGORITHM_HEADER_KEY) {
        Some(header) => {
            if header.to_str()? != gcs::CSEK_ENCRYPTION_ALGORITHM {
                anyhow::bail!("Unexpected encryption algorithm in server response.");
            } else {
                header.to_str()?
            }
        }
        None => anyhow::bail!("Couldn't find encryption algorithm header in server response"),
    };

    match response_headers.get(gcs::CSEK_ENCRYPTION_KEY_SHA256_HEADER_KEY) {
        Some(header) => {
            if header.to_str()? != csek_base64_of_sha256_of_encryption_key {
                anyhow::bail!("Unexpected encryption key hash in server response.");
            } else {
                header.to_str()?
            }
        }
        None => anyhow::bail!("Couldn't find encryption key SHA256 header in server response."),
    };
    Ok(())
}

fn validate_multipart_upload_part_query_and_headers(
    request_query: &str,
    response_headers: &HeaderMap,
) -> bool {
    request_query.contains("partNumber=")
        && response_headers.contains_key(http::header::ETAG)
        && response_headers.contains_key(gcs::HASH_HEADER_KEY)
}
fn validate_multipart_upload_finish_headers(response_headers: &HeaderMap) -> bool {
    response_headers.contains_key(gcs::GENERATION_HEADER_KEY)
        && response_headers.contains_key(gcs::METAGENERATION_HEADER_KEY)
        && response_headers.contains_key(gcs::STORED_CONTENT_LENGTH_HEADER_KEY)
}
