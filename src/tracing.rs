use crate::SUBSEQ_UTIL_VERSION;
use tracing_log::LogTracer;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::prelude::*;

pub fn setup_tracing(app_name: &str, filter_level: Option<String>) {
    let default_log_levels = format!("{}=debug,subseq_util=debug", app_name);
    let logger = LogTracer::new();
    log::set_boxed_logger(Box::new(logger)).unwrap();
    log::set_max_level(log::LevelFilter::Trace);

    #[cfg(debug_assertions)]
    {
        let tracing_layer = tracing_subscriber::fmt::layer()
            .compact()
            .with_level(true)
            .with_thread_ids(true)
            .with_line_number(true)
            .with_file(true);

        #[cfg(feature = "console")]
        {
            let console_layer = console_subscriber::spawn();
            let filter_layer = if let Some(filter_level) = filter_level.as_ref() {
                EnvFilter::new(filter_level)
            } else {
                EnvFilter::new(default_log_levels.as_str())
            };
            tracing_subscriber::registry()
                .with(filter_layer)
                .with(console_layer)
                .with(tracing_layer)
                .init();
        }
        #[cfg(not(feature = "console"))]
        {
            let filter_layer = if let Some(filter_level) = filter_level.as_ref() {
                EnvFilter::new(filter_level)
            } else {
                EnvFilter::new(default_log_levels.as_str())
            };
            tracing_subscriber::registry()
                .with(filter_layer)
                .with(tracing_layer)
                .init();
            tracing::info!("Tracing started without console: {:?}", filter_level);
        }
    }
    #[cfg(not(debug_assertions))]
    {
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
    }
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
