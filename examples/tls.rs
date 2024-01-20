use std::env;
use std::fs::File;

use subseq_util::{
    api::{authenticate, handle_rejection, init_session_store, sessions, AuthenticatedUser},
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

    // Routes
    let session = init_session_store();
    let routes = sessions::no_auth_routes(session.clone())
        .or(warp::get()
            .and(authenticate(None, session.clone()))
            .and_then(hello_world))
        .recover(handle_rejection);

    warp::serve(routes)
        .tls()
        .cert_path(&conf.tls.cert_path)
        .key_path(&conf.tls.key_path)
        .run(([127, 0, 0, 1], 8443))
        .await;
}
