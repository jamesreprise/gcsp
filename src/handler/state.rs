use crate::config::ProxyConfig;

#[derive(Clone)]
pub(crate) struct ProxyState {
    pub(crate) config: ProxyConfig,
    pub(crate) http_client: reqwest::Client,
}
