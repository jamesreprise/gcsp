mod config;
mod handler;
mod logging;
mod metrics;

use anyhow::Result;
use axum::handler::Handler;
use axum::middleware;
use clap::Parser;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::config::ProxyConfig;
use crate::handler::middleware as handler_middleware;
use crate::handler::proxy::proxy;
use crate::handler::state::ProxyState;

#[derive(Parser, Debug)]
#[command(version, about)]
pub(crate) struct Args {
    #[arg(long, default_value = "config.toml")]
    config_file: String,

    #[arg(long, default_value = "info")]
    log_level: String,

    #[arg(long, action)]
    json: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    logging::init(&args);

    let config: ProxyConfig =
        toml::from_str(&std::fs::read_to_string(args.config_file)?)?;

    config.validate()?;

    let loopback_address = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let metrics_socket_addr =
        SocketAddr::new(loopback_address, config.metrics_port);
    metrics::init(metrics_socket_addr);

    let state: ProxyState = ProxyState {
        config: config.clone(),
        http_client: http_client()?,
    };

    let proxy_socket_addr =
        SocketAddr::new(loopback_address, config.proxy_port);

    let listener = tokio::net::TcpListener::bind(proxy_socket_addr)
        .await
        .unwrap();

    tracing::info!("Starting server on {proxy_socket_addr}...");

    let make_service = proxy
        .layer(middleware::from_fn(handler_middleware::metrics))
        .with_state(state)
        .into_make_service();
    axum::serve(listener, make_service).await?;

    Ok(())
}

fn http_client() -> Result<reqwest::Client> {
    let http_client = reqwest::Client::builder()
        .https_only(true)
        //.http1_only()
        .build()?;
    Ok(http_client)
}
