use serde::Deserialize;

#[derive(Clone)]
pub(crate) struct ProxyState {
    pub(crate) config: ProxyConfig,
    pub(crate) http_client: reqwest::Client,
}

#[derive(Deserialize, Clone, Debug)]
pub(crate) struct ProxyConfig {
    pub(crate) hmac_access_key: String,
    pub(crate) hmac_secret_key: String,
    pub(crate) csek_encryption_key: String,
}
