mod handler;
mod logging;
mod metrics;

use anyhow::Result;
use axum::handler::Handler;
use axum::middleware;
use clap::Parser;

use crate::handler::config::{ProxyConfig, ProxyState};
use crate::handler::middleware as handler_middleware;
use crate::handler::proxy::proxy;

const ADDRESS: &str = "0.0.0.0:7000";

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

    metrics::init();

    let config: ProxyConfig = toml::from_str(&std::fs::read_to_string(args.config_file)?)?;
    let state: ProxyState = ProxyState {
        config,
        http_client: http_client()?,
    };

    let listener = tokio::net::TcpListener::bind(ADDRESS).await.unwrap();

    tracing::info!("Starting server on {ADDRESS}...");

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
