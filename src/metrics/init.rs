use std::{net::SocketAddr, num::NonZero, time::Duration};

use metrics_exporter_prometheus::{self, PrometheusBuilder};

pub(crate) fn init(addr: SocketAddr) {
    PrometheusBuilder::new()
        .with_http_listener(addr)
        .set_bucket_duration(Duration::from_secs(60))
        .unwrap()
        .set_bucket_count(NonZero::new(5).unwrap())
        .install()
        .unwrap();
}
