use anyhow::Result;
use axum::http;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use itertools::{join, sorted, Itertools};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::instrument;

use super::gcs;

pub(crate) struct GCPCredentials {
    pub(crate) hmac_access_key: String,
    pub(crate) hmac_secret_key: String,
}

pub(crate) struct GCPSignature {
    pub(crate) auth_header: String,
    pub(crate) goog_date: String,
    pub(crate) payload_hash: String,
}

pub(crate) struct GCPSignatureRequest<'a> {
    pub(crate) credentials: GCPCredentials,
    pub(crate) csek_encryption_key: String,
    pub(crate) csek_encryption_key_sha256: String,
    pub(crate) datetime: DateTime<Utc>,
    pub(crate) region: String,
    pub(crate) method: http::Method,
    pub(crate) path: String,
    pub(crate) query: String,
    // Take only a reference to the body of the request as it may be reasonably large (10MB).
    // Requires the use of a lifetime.
    pub(crate) body: &'a [u8],
}

impl GCPSignatureRequest<'_> {
    #[instrument(skip_all, level = tracing::Level::DEBUG)]
    pub(crate) fn sign(&self) -> Result<GCPSignature> {
        let goog_date = self.datetime.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = self.datetime.format("%Y%m%d").to_string();

        let mut canonical_headers: HashMap<String, String> = HashMap::new();
        canonical_headers
            .insert(http::header::HOST.to_string(), gcs::HOST.to_string());
        canonical_headers
            .insert(gcs::DATE_HEADER_KEY.to_string(), goog_date.clone());
        canonical_headers.insert(
            gcs::CSEK_ENCRYPTION_ALGORITHM_HEADER_KEY.to_string(),
            gcs::CSEK_ENCRYPTION_ALGORITHM.to_string(),
        );
        canonical_headers.insert(
            gcs::CSEK_ENCRYPTION_KEY_HEADER_KEY.to_string(),
            self.csek_encryption_key.clone(),
        );
        canonical_headers.insert(
            gcs::CSEK_ENCRYPTION_KEY_SHA256_HEADER_KEY.to_string(),
            self.csek_encryption_key_sha256.clone(),
        );

        // Derive signed headers from our canonical headers.
        let signed_headers = canonical_headers.keys().sorted().join(";");

        // Sort the canonical headers before formatting them as a string.
        let canonical_headers_string = canonical_headers
            .iter()
            .sorted_by_key(|(k, _)| *k)
            .map(|(k, v)| format!("{k}:{v}"))
            .join("\n");

        let payload_hash = hex::encode(sha2::Sha256::digest(self.body));

        let canonical_query_string = join(sorted(self.query.split("&")), "&");
        // Structure must be exactly as per https://cloud.google.com/storage/docs/authentication/canonical-requests
        let canonical_request = [
            self.method.to_string(),
            self.path.to_string(),
            canonical_query_string,
            canonical_headers_string + "\n", // Newline after headers to denote their end.
            signed_headers.clone(),
            payload_hash.clone(),
        ]
        .join("\n");

        tracing::debug!(?canonical_request);

        let credential_scope = format!(
            "{date_stamp}/{region}/{service}/{signature_type}",
            region = self.region,
            service = gcs::SERVICE_NAME,
            signature_type = gcs::V4_SIGNATURE_REQUEST_TYPE
        );

        // Structure must be exactly as per https://cloud.google.com/storage/docs/authentication/signatures
        let string_to_sign = format!(
            "{algorithm}\n{goog_date}\n{credential_scope}\n{canonical_request_sha256_hex}",
            algorithm = gcs::V4_SIGNATURE_ALGORITHM,
            canonical_request_sha256_hex =
                hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );

        tracing::debug!(?string_to_sign);

        // Order must be exactly as per https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html
        let date_key = hmac_sha256(
            format!(
                "{v4_signature_hmac_prefix}{hmac_secret_key}",
                v4_signature_hmac_prefix = gcs::V4_SIGNATURE_HMAC_PREFIX,
                hmac_secret_key = self.credentials.hmac_secret_key
            )
            .as_bytes(),
            date_stamp.as_bytes(),
        )?;

        let date_region_key = hmac_sha256(&date_key, self.region.as_bytes())?;
        let date_region_service_key =
            hmac_sha256(&date_region_key, gcs::SERVICE_NAME.as_bytes())?;
        let signing_key = hmac_sha256(
            &date_region_service_key,
            gcs::V4_SIGNATURE_REQUEST_TYPE.as_bytes(),
        )?;
        let signature =
            hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes())?);

        let credential = format!(
            "{hmac_access_key}/{credential_scope}",
            hmac_access_key = self.credentials.hmac_access_key
        );
        // Must be exactly as per https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html
        let auth_header = format!(
            "{algorithm} Credential={credential}, SignedHeaders={signed_headers}, Signature={signature}",
            algorithm = gcs::V4_SIGNATURE_ALGORITHM
        );

        Ok(GCPSignature {
            auth_header,
            goog_date,
            payload_hash,
        })
    }
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)?;
    mac.update(msg);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcp_signature_no_body() -> Result<()> {
        let GCPSignature {
            auth_header,
            goog_date,
            payload_hash,
        } = GCPSignatureRequest {
            credentials: GCPCredentials {
                hmac_access_key: "GOOGTS7C7FUP3AIRVJTE2BCDKINBTES3HC2GY5CBFJDCQ2SYHV6A6XXVTJFSA"
                    .to_string(),
                hmac_secret_key: "bGoa+V7g/yqDXvKRqq+JTFn4uQZbPiQJo4pf9RzJ".to_string(),
            },
            csek_encryption_key: "xH7BtNooA2sIi407GFShu2ptk/GXNnNShVHqNSqS3o4=".to_string(),
            csek_encryption_key_sha256: "qY3tWr71bsAVBGFgWA2wsMYIgw71Ko2HMA/Yj6DG0sU=".to_string(),
            region: "europe-west6".to_string(),
            method: http::Method::GET,
            path: "/griffin-foundationdb-backups-dev-europe-west6".to_string(),
            query: "".to_string(),
            datetime: DateTime::UNIX_EPOCH,
            body: &[],
        }
        .sign()?;

        assert_eq!(goog_date, "19700101T000000Z");
        assert_eq!(auth_header, "GOOG4-HMAC-SHA256 Credential=GOOGTS7C7FUP3AIRVJTE2BCDKINBTES3HC2GY5CBFJDCQ2SYHV6A6XXVTJFSA/19700101/europe-west6/storage/goog4_request, SignedHeaders=host;x-goog-date;x-goog-encryption-algorithm;x-goog-encryption-key;x-goog-encryption-key-sha256, Signature=8e3984d84e2e5b84585ec6f7bb1418e2cc4962a4f8d3daebee661479c99ea71c");
        assert_eq!(
            payload_hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        Ok(())
    }

    #[test]
    fn gcp_signature_with_body() -> Result<()> {
        let GCPSignature {
            auth_header,
            goog_date,
            payload_hash,
        } = GCPSignatureRequest {
            credentials: GCPCredentials {
                hmac_access_key: "GOOGTS7C7FUP3AIRVJTE2BCDKINBTES3HC2GY5CBFJDCQ2SYHV6A6XXVTJFSA"
                    .to_string(),
                hmac_secret_key: "bGoa+V7g/yqDXvKRqq+JTFn4uQZbPiQJo4pf9RzJ".to_string(),
            },
            csek_encryption_key: "xH7BtNooA2sIi407GFShu2ptk/GXNnNShVHqNSqS3o4=".to_string(),
            csek_encryption_key_sha256: "qY3tWr71bsAVBGFgWA2wsMYIgw71Ko2HMA/Yj6DG0sU=".to_string(),
            region: "europe-west6".to_string(),
            method: http::Method::GET,
            path: "/griffin-foundationdb-backups-dev-europe-west6".to_string(),
            query: "".to_string(),
            datetime: DateTime::UNIX_EPOCH,
            body: &[1],
        }
        .sign()?;

        assert_eq!(goog_date, "19700101T000000Z");
        assert_eq!(auth_header, "GOOG4-HMAC-SHA256 Credential=GOOGTS7C7FUP3AIRVJTE2BCDKINBTES3HC2GY5CBFJDCQ2SYHV6A6XXVTJFSA/19700101/europe-west6/storage/goog4_request, SignedHeaders=host;x-goog-date;x-goog-encryption-algorithm;x-goog-encryption-key;x-goog-encryption-key-sha256, Signature=a8efc4f017c1fc0cbf189887ece6af2e22d61e5bb13b70dcb49df5ec33361a0a");
        assert_eq!(
            payload_hash,
            "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"
        );

        Ok(())
    }
}
