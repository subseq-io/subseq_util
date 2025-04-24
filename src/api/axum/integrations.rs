use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Json, State},
    response::IntoResponse,
    routing::get,
    Router,
};
use serde_json::Value;
use tokio::task::spawn;

use crate::api::axum::{AppState, Integration};
use crate::api::{AuthenticatedUser, RejectReason};
use crate::tables::DbPool;
use crate::UserId;

async fn get_integrations_handler(
    auth_user: AuthenticatedUser,
    State(app): State<AppState>,
) -> Result<impl IntoResponse, RejectReason> {
    let results = get_integrations(
        app.db_pool.clone(),
        auth_user.id(),
        app.integrations.clone(),
    )
    .await?;
    Ok(Json(results))
}

async fn get_integrations(
    db_pool: Arc<DbPool>,
    user_id: UserId,
    integrations: Vec<Arc<dyn Integration + Send + Sync>>,
) -> Result<HashMap<&'static str, Value>, RejectReason> {
    // Fetch each account in parallel because they are independent of each other
    let mut tasks = HashMap::new();
    for integration in integrations {
        let pool = db_pool.clone();
        let name = integration.name();
        tasks.insert(
            name,
            spawn(async move { integration.get(pool, user_id).await }),
        );
    }
    let mut results = HashMap::new();
    for (name, task) in tasks {
        match task.await {
            Ok(result) => {
                match result {
                    Ok(value) => results.insert(name, value),
                    Err(e) => {
                        tracing::error!("Error fetching integration {}: {:?}", name, e);
                        continue;
                    }
                };
            }
            Err(e) => {
                return Err(RejectReason::anyhow(anyhow::anyhow!(
                    "Task JoinError: {:?}",
                    e
                )));
            }
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    use serde_json::{json, Value};

    use crate::api::axum::Integration;
    use crate::server::DatabaseConfig;
    use crate::tables::establish_connection_pool;
    use crate::tables::DbPool;
    use crate::tables::UserId;
    use uuid::Uuid;

    struct TestIntegration;

    impl Integration for TestIntegration {
        fn name(&self) -> &'static str {
            "test_integration"
        }

        fn create(
            &self,
            _pool: Arc<DbPool>,
            _user_id: UserId,
            _data: Value,
        ) -> Pin<Box<dyn Future<Output = Result<Uuid, RejectReason>> + Send>> {
            Box::pin(async { Ok(Uuid::new_v4()) })
        }

        fn get(
            &self,
            _pool: Arc<DbPool>,
            _user_id: UserId,
        ) -> Pin<Box<dyn Future<Output = Result<Value, RejectReason>> + Send>> {
            Box::pin(async { Ok(json!({"key": "value"})) })
        }
    }

    #[tokio::test]
    #[named]
    async fn test_get_integrations() {
        let harness = DbHarness::new("localhost", "development", &db_name, None).await;
        let pool = harness.pool().await;
        let integrations: Vec<Arc<dyn Integration + Send + Sync>> = vec![Arc::new(TestIntegration)];

        let result = get_integrations(db_pool, UserId(Uuid::new_v4()), integrations)
            .await
            .expect("Failed to get integrations");

        assert_eq!(result.len(), 1);
        assert_eq!(result["test_integration"]["key"], "value");
    }
}

pub fn routes() -> Router<AppState> {
    tracing::debug!("Included integrations routes");
    Router::new().route("/integrations", get(get_integrations_handler))
}
