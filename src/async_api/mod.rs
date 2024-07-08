use std::sync::Arc;
use warp::{http::StatusCode, Filter, Rejection, Reply};

pub mod email;

use crate::async_tables::DbPool;

pub fn with_db(
    pool: Arc<DbPool>,
) -> impl Filter<Extract = (Arc<DbPool>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || pool.clone())
}
