use crate::SUBSEQ_UTIL_VERSION;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::prelude::*;

pub fn setup_tracing(app_name: &str, filter_level: Option<String>) {
    let default_log_levels = format!("{}=debug,subseq_util=debug", app_name);
    let tracing_layer = tracing_subscriber::fmt::layer().compact().with_level(true);
    let filter_layer = if let Some(filter_level) = filter_level.as_ref() {
        EnvFilter::new(filter_level)
    } else {
        EnvFilter::new(default_log_levels.as_str())
    };
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(tracing_layer)
        .init();
    tracing::info!(
        "Tracing started: {}",
        if let Some(filter_level) = filter_level {
            filter_level
        } else {
            default_log_levels
        }
    );
    tracing::info!(
        "App '{}' started (subseq_util: {})",
        app_name,
        SUBSEQ_UTIL_VERSION
    );
}
