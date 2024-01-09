use std::env;
use serde::Deserialize;
use url::Url;

pub trait EnvFilledConfig: Sized {
    fn fill_from_env(self) -> Result<Self, env::VarError>;
}

#[derive(Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub ca_path: String,
}

impl EnvFilledConfig for TlsConfig {
    fn fill_from_env(self) -> Result<Self, env::VarError> {
        Ok(Self {
            cert_path: env::var("SERVER_TLS_CERT").unwrap_or(self.cert_path),
            key_path: env::var("SERVER_TLS_KEY").unwrap_or(self.key_path),
            ca_path: env::var("SERVER_TLS_CA").unwrap_or(self.ca_path),
        })
    }
}

#[derive(Deserialize)]
pub struct PrismConfig {
    pub host: String,
    pub port: u16,
}

impl EnvFilledConfig for PrismConfig {
    fn fill_from_env(self) -> Result<Self, env::VarError> {
        let port = match env::var("PRISM_PORT") {
            Ok(port) => match port.parse::<u16>() {
                Ok(port) => port,
                Err(_) => self.port
            },
            Err(_) => self.port
        };
        Ok(Self {
            host: env::var("PRISM_HOST").unwrap_or(self.host),
            port,
        })
    }
}

#[derive(Deserialize)]
pub struct OidcConfig {
    pub idp_url: Url,
    pub client_id: String,
    pub client_secret: Option<String>,
}

impl EnvFilledConfig for OidcConfig {
    fn fill_from_env(self) -> Result<Self, env::VarError> {
        let idp_url = match env::var("OIDC_IDP_URL") {
            Ok(url) => match Url::parse(&url) {
                Ok(url) => url,
                Err(_) => self.idp_url
            }
            Err(_) => self.idp_url
        };

        Ok(Self {
            idp_url,
            client_id: env::var("OIDC_CLIENT_ID").unwrap_or(self.client_id),
            client_secret: Some(env::var("OIDC_CLIENT_SECRET")?),
        })
    }
}

#[derive(Deserialize)]
pub struct DatabaseConfig {
    pub username: String,
    pub password: Option<String>,
    pub host: String,
    pub port: u16,
    pub require_ssl: bool
}

impl EnvFilledConfig for DatabaseConfig {
    fn fill_from_env(self) -> Result<Self, env::VarError> {
        let port = match env::var("PGPORT") {
            Ok(port) => match port.parse::<u16>() {
                Ok(port) => port,
                Err(_) => self.port
            },
            Err(_) => self.port
        };
        Ok(Self {
            username: env::var("PGUSER").unwrap_or(self.username),
            password: Some(env::var("PGPASSWORD")?),
            host: env::var("PGHOST").unwrap_or(self.host),
            port,
            require_ssl: env::var("PGREQUIRESSL")
                .map(|y| !y.is_empty())
                .unwrap_or(false)
        })
    }
}

impl DatabaseConfig {
    pub fn db_url(self, database: &str) -> String {
        let ssl_string = "?sslmode=require";
        format!("postgres://{}:{}@{}:{}/{}{}",
                self.username,
                self.password.expect("No password for database!"),
                self.host,
                self.port,
                database,
                if self.require_ssl {ssl_string} else {""})
    }
}

#[derive(Deserialize)]
pub struct BaseConfig {
    pub tls: TlsConfig,
    pub prism: PrismConfig,
    pub oidc: OidcConfig,
    pub database: DatabaseConfig,
}

pub struct InnerConfig {
    pub tls: TlsConfig,
    pub prism: PrismConfig,
    pub oidc: OidcConfig,
    pub database: DatabaseConfig,
}

impl TryFrom<BaseConfig> for InnerConfig {
    type Error = std::env::VarError;

    fn try_from(conf: BaseConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            tls: conf.tls.fill_from_env()?,
            prism: conf.prism.fill_from_env()?,
            oidc: conf.oidc.fill_from_env()?,
            database: conf.database.fill_from_env()?
        })
    }
}
