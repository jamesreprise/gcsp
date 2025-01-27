pub(crate) const HOST: &str = "storage.googleapis.com";
pub(crate) const PORT: &str = "443";

pub(crate) const SERVICE_NAME: &str = "storage";

pub(crate) const V4_SIGNATURE_ALGORITHM: &str = "GOOG4-HMAC-SHA256";
pub(crate) const V4_SIGNATURE_REQUEST_TYPE: &str = "goog4_request";
pub(crate) const V4_SIGNATURE_HMAC_PREFIX: &str = "GOOG4";

pub(crate) const CSEK_ENCRYPTION_ALGORITHM_HEADER_KEY: &str = "x-goog-encryption-algorithm";
pub(crate) const CSEK_ENCRYPTION_ALGORITHM: &str = "AES256";
pub(crate) const CSEK_ENCRYPTION_KEY_HEADER_KEY: &str = "x-goog-encryption-key";
pub(crate) const CSEK_ENCRYPTION_KEY_SHA256_HEADER_KEY: &str = "x-goog-encryption-key-sha256";

pub(crate) const DATE_HEADER_KEY: &str = "x-goog-date";
pub(crate) const HASH_HEADER_KEY: &str = "x-goog-hash";
pub(crate) const GENERATION_HEADER_KEY: &str = "x-goog-generation";
pub(crate) const METAGENERATION_HEADER_KEY: &str = "x-goog-metageneration";
pub(crate) const CONTENT_SHA256_HEADER_KEY: &str = "x-goog-content-sha256";
pub(crate) const STORED_CONTENT_LENGTH_HEADER_KEY: &str = "x-goog-stored-content-length";

pub(crate) const AMZ_HEADER_KEY_PREFIX: &str = "x-amz-";

// 5GB: GCS's upper bound for multipart upload sizes.
// If you're hitting this: what's going on, big guy?
pub(crate) const REQUEST_SIZE_BYTES_UPPERBOUND: usize = 5 * 1024 * 1024 * 1024;
