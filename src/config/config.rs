use anyhow::{Error, Result};
use base64::prelude::*;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const fn _default_proxy_port() -> u16 { 60061 }
const fn _default_metrics_port() -> u16 { 60062 }

#[derive(Deserialize, Clone, Debug)]
pub(crate) struct ProxyConfig {
    #[serde(default = "_default_proxy_port")]
    pub(crate) proxy_port: u16,
    #[serde(default = "_default_metrics_port")]
    pub(crate) metrics_port: u16,
    pub(crate) hmac_access_key: String,
    pub(crate) hmac_secret_key: String,
    pub(crate) csek_encryption_key: String,
    pub(crate) csek_encryption_key_sha256: String,
}

impl ProxyConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        let csek_encryption_key_sha256 =
            csek_encryption_key_sha256(&self.csek_encryption_key)?;
        match csek_encryption_key_sha256 == self.csek_encryption_key_sha256 {
            true => Ok(()),
            false => Err(Error::msg(format!("Calculated CSEK SHA256 \"{csek_encryption_key_sha256}\" did not match config."))),
        }
    }
}

fn csek_encryption_key_sha256(key: &str) -> Result<String> {
    Ok(BASE64_STANDARD.encode(Sha256::digest(BASE64_STANDARD.decode(key)?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn csek_sha256() -> Result<()> {
        assert_eq!(
            csek_encryption_key_sha256(
                "xH7BtNooA2sIi407GFShu2ptk/GXNnNShVHqNSqS3o4="
            )?,
            "qY3tWr71bsAVBGFgWA2wsMYIgw71Ko2HMA/Yj6DG0sU=".to_string()
        );
        Ok(())
    }
}
