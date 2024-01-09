use std::sync::Arc;
use std::env;
use std::fs::File;

use subseq_util::{
    BaseConfig,
    InnerConfig,
    oidc::{init_client_pool, IdentityProvider, OidcCredentials},
    tracing::setup_tracing,
    api::{init_session_store, authenticate, sessions, handle_rejection, AuthenticatedUser}, 
};
use warp::{Filter, Rejection, Reply};

pub async fn hello_world(user: AuthenticatedUser)
    -> Result<impl Reply, Rejection>
{
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
    let conf: InnerConfig = conf.try_into().expect("Could not fetch all secrets from environment");

    // OIDC
    init_client_pool(&conf.tls.ca_path);
    let redirect_url = "https://localhost:8443/auth";
    let oidc = OidcCredentials::new(&conf.oidc.client_id,
                                    &conf.oidc.client_secret.expect("No OIDC Client Secret"),
                                    redirect_url)
        .expect("Invalid OIDC Credentials");
    let idp = IdentityProvider::new(&oidc, &conf.oidc.idp_url.to_string()).await
        .expect("Failed to establish Identity Provider connection");
    let idp = Arc::new(idp);

    // Routes
    let session = init_session_store();
    let routes = sessions::routes(session.clone(), idp.clone())
        .or(warp::get()
            .and(authenticate(idp.clone(), session.clone()))
            .and_then(hello_world))
        .recover(handle_rejection);

    warp::serve(routes)
        .tls()
        .cert_path(&conf.tls.cert_path)
        .key_path(&conf.tls.key_path)
        .run(([127, 0, 0, 1], 8443)).await;
}
