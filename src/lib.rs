pub mod ids;
pub mod prelude;
pub mod typed_id;
pub mod typed_uuid;

// Re-exported for `typed_id!` expansions, so callers need no direct dependency.
#[cfg(feature = "schemars")]
#[doc(hidden)]
pub use schemars as __schemars;
#[cfg(feature = "sqlx")]
#[doc(hidden)]
pub use sqlx as __sqlx;

include!(concat!(env!("OUT_DIR"), "/version.rs"));
