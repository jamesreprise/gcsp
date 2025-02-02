use std::str::FromStr;
use tracing::{level_filters::LevelFilter, Level};
use tracing_subscriber::{
    fmt::{format::FmtSpan, Layer},
    prelude::*,
};

use crate::Args;

pub fn init(args: &Args) {
    let log_level_filter =
        LevelFilter::from_level(Level::from_str(&args.log_level).unwrap());

    let default_fmt_layer = Layer::default();
    let fmt = match args.json {
        true => default_fmt_layer
            .json()
            .with_span_events(FmtSpan::CLOSE)
            .with_filter(log_level_filter)
            .boxed(),
        false => default_fmt_layer
            .with_span_events(FmtSpan::CLOSE)
            .with_filter(log_level_filter)
            .boxed(),
    };

    tracing_subscriber::registry().with(fmt).init();
}
