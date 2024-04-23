use std::env;
use std::fs::File;
use std::sync::Arc;

use subseq_util::{
    api::{authenticate, handle_rejection, init_session_store, sessions, AuthenticatedUser},
    oidc::{init_client_pool, IdentityProvider, OidcCredentials},
    tracing::setup_tracing,
    BaseConfig, InnerConfig,
};
use warp::{Filter, Rejection, Reply};

pub async fn hello_world(user: AuthenticatedUser) -> Result<impl Reply, Rejection> {
    let body = format!("<html>Hello {}!</html>", user.id());
    Ok(warp::reply::html(body))
}

#[tokio::main]
async fn main() {
    setup_tracing("example");
    let args: Vec<String> = env::args().collect();
    let conf_path = args.last().expect("Need a configuration file").clone();
    let conf_file = File::open(&conf_path).expect("Could not open config file");
    let conf: BaseConfig = serde_json::from_reader(conf_file).expect("Reading config failed");
    let conf: InnerConfig = conf
        .try_into()
        .expect("Could not fetch all secrets from environment");

    // OIDC
    let tls_conf = conf.tls.as_ref().expect("Must define TLS for this example");
    let oidc_conf = conf
        .oidc
        .as_ref()
        .expect("Must define OIDC for this example");

    init_client_pool(tls_conf.ca_path.expect("Need CA path in example").as_str());
    let redirect_url = "https://localhost:8443/auth";
    let oidc = OidcCredentials::new(
        oidc_conf.client_id.clone(),
        oidc_conf
            .client_secret
            .as_ref()
            .expect("No OIDC Client Secret")
            .clone(),
        redirect_url,
    )
    .expect("Invalid OIDC Credentials");
    let idp = IdentityProvider::new(&oidc, &oidc_conf.idp_url.to_string())
        .await
        .expect("Failed to establish Identity Provider connection");
    let idp = Arc::new(idp);

    // Routes
    let session = init_session_store();
    let routes = sessions::routes(session.clone(), idp.clone())
        .or(warp::get()
            .and(authenticate(Some(idp.clone()), session.clone()))
            .and_then(hello_world))
        .recover(handle_rejection);

    warp::serve(routes)
        .tls()
        .cert_path(tls_conf.cert_path.as_str())
        .key_path(tls_conf.key_path.as_str())
        .run(([127, 0, 0, 1], 8443))
        .await;
}
