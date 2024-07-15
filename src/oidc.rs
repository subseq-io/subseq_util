use std::str::FromStr;

use anyhow::{anyhow, Result as AnyResult};
use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreIdToken, CoreIdTokenClaims, CoreTokenResponse,
};
use openidconnect::reqwest::Error as RequestError;
use openidconnect::{
    AccessToken, AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EndSessionUrl, HttpRequest, HttpResponse, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, ProviderMetadataWithLogout, RedirectUrl, RefreshToken,
    Scope, TokenResponse,
};
use reqwest::{redirect::Policy, Client};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::get_cert_pool;

fn new_client() -> Client {
    let mut builder = Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .redirect(Policy::none())
        .tcp_nodelay(true)
        .tls_built_in_root_certs(true);

    if let Some(cert_pool) = get_cert_pool() {
        for cert in cert_pool.certs().iter() {
            builder = builder.add_root_certificate(cert.clone());
        }
    }
    builder.build().unwrap()
}

pub async fn async_http_client(
    request: HttpRequest,
) -> Result<HttpResponse, RequestError<reqwest::Error>> {
    let client = new_client();

    let mut request_builder = client
        .request(request.method, request.url.as_str())
        .body(request.body);
    for (name, value) in &request.headers {
        request_builder = request_builder.header(name.as_str(), value.as_bytes());
    }
    let request = request_builder.build().map_err(RequestError::Reqwest)?;

    let response = client
        .execute(request)
        .await
        .map_err(RequestError::Reqwest)?;

    let status_code = response.status();
    let headers = response.headers().to_owned();
    let chunks = response.bytes().await.map_err(RequestError::Reqwest)?;
    Ok(HttpResponse {
        status_code,
        headers,
        body: chunks.to_vec(),
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OidcToken {
    id_token: CoreIdToken,
    access_token: AccessToken,
    refresh_token: Option<RefreshToken>,
    nonce: Nonce,
}

impl OidcToken {
    fn from_token_response(token: CoreTokenResponse, nonce: Nonce) -> AnyResult<Self> {
        tracing::trace!("from_token_response");
        tracing::trace!("id_token: {:?}", token.id_token());
        tracing::trace!("access_token: {:?}", token.access_token());
        tracing::trace!("refresh_token: {:?}", token.refresh_token());
        Ok(Self {
            id_token: token
                .id_token()
                .cloned()
                .ok_or_else(|| anyhow!("Server did not provide ID token!"))?,
            access_token: token.access_token().clone(),
            refresh_token: token.refresh_token().cloned(),
            nonce,
        })
    }

    pub fn refresh(self, token: CoreTokenResponse) -> Option<Self> {
        Some(Self {
            id_token: token.id_token().cloned()?,
            access_token: token.access_token().clone(),
            refresh_token: token.refresh_token().cloned(),
            nonce: self.nonce,
        })
    }

    pub fn from_bearer(tok: &str) -> Option<Self> {
        let parts: Vec<&str> = tok.split(':').collect();
        if parts.len() == 3 {
            Some(OidcToken {
                id_token: CoreIdToken::from_str(parts[0]).ok()?,
                access_token: AccessToken::new(parts[1].to_string()),
                refresh_token: None,
                nonce: Nonce::new(parts[2].to_string()),
            })
        } else if parts.len() == 4 {
            Some(OidcToken {
                id_token: CoreIdToken::from_str(parts[0]).ok()?,
                access_token: AccessToken::new(parts[1].to_string()),
                refresh_token: Some(RefreshToken::new(parts[2].to_string())),
                nonce: Nonce::new(parts[3].to_string()),
            })
        } else {
            None
        }
    }
}

pub struct OidcCredentials {
    client_id: ClientId,
    client_secret: ClientSecret,
    base_url: Url,
    redirect_url: RedirectUrl,
}

impl OidcCredentials {
    pub fn new<A: Into<String>, B: Into<String>, C: Into<String>, D: Into<String>>(
        client_id: A,
        client_secret: B,
        base_url: C,
        redirect_url: D,
    ) -> AnyResult<Self> {
        Ok(Self {
            client_id: ClientId::new(client_id.into()),
            client_secret: ClientSecret::new(client_secret.into()),
            base_url: Url::parse(&base_url.into())?,
            redirect_url: RedirectUrl::new(redirect_url.into())?,
        })
    }
}

pub struct IdentityProvider {
    client: CoreClient,
    base_url: Url,
    logout_url: EndSessionUrl,
}

impl IdentityProvider {
    pub async fn new(oidc: &OidcCredentials, idp_url: &Url) -> AnyResult<Self> {
        tracing::info!("OIDC server: {}", idp_url);
        let config = provider_metadata(idp_url).await?;
        let logout_url = config
            .additional_metadata()
            .end_session_endpoint
            .clone()
            .ok_or_else(|| anyhow!("No logout URL"))?;

        let client = CoreClient::from_provider_metadata(
            config,
            oidc.client_id.clone(),
            Some(oidc.client_secret.clone()),
        )
        .set_redirect_uri(oidc.redirect_url.clone());

        Ok(Self {
            client,
            base_url: oidc.base_url.clone(),
            logout_url,
        })
    }

    pub async fn refresh(&self, token: OidcToken) -> AnyResult<OidcToken> {
        let refresh_token = match &token.refresh_token {
            Some(tok) => tok,
            None => anyhow::bail!("No refresh token"),
        };
        tracing::trace!("refresh request refresh_token: {:?}", refresh_token);
        let token_response = self
            .client
            .exchange_refresh_token(refresh_token)
            .request_async(async_http_client)
            .await?;
        match token.refresh(token_response) {
            Some(token) => Ok(token),
            None => anyhow::bail!("Missing token"),
        }
    }

    pub fn login_oidc(&self, scopes: Vec<String>) -> (Url, CsrfToken, PkceCodeVerifier, Nonce) {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut auth_builder = self.client.authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );
        for scope in scopes {
            auth_builder = auth_builder.add_scope(Scope::new(scope));
        }
        let (auth_url, csrf_token, nonce) = auth_builder.set_pkce_challenge(challenge).url();
        (auth_url, csrf_token, verifier, nonce)
    }

    pub fn logout_oidc(&self, redirect_uri: &str, token: &OidcToken) -> Url {
        let mut logout_url = self.logout_url.url().clone();
        let redirect_uri = format!("{}{}", self.base_url, redirect_uri);
        logout_url
            .query_pairs_mut()
            .append_pair("id_token_hint", &token.id_token.to_string())
            .append_pair("post_logout_redirect_uri", &redirect_uri);
        logout_url
    }

    pub async fn token_oidc(
        &self,
        code: AuthorizationCode,
        verifier: PkceCodeVerifier,
        nonce: Nonce,
    ) -> AnyResult<OidcToken> {
        let token_response = self
            .client
            .exchange_code(code)
            .set_pkce_verifier(verifier)
            .request_async(async_http_client)
            .await?;
        let oidc_token = OidcToken::from_token_response(token_response, nonce)?;
        self.validate_token(&oidc_token)?;
        Ok(oidc_token)
    }

    pub fn validate_token(&self, token: &OidcToken) -> AnyResult<CoreIdTokenClaims> {
        let verifier = self.client.id_token_verifier();
        let id_token = &token.id_token;
        tracing::trace!("claims");
        let claims = id_token.claims(&verifier, &token.nonce)?;
        tracing::trace!("after claims");

        if let Some(expected_access_token_hash) = claims.access_token_hash() {
            tracing::trace!("in hash");
            let actual_access_token_hash =
                AccessTokenHash::from_token(&token.access_token, &id_token.signing_alg()?)?;
            tracing::trace!("after hash get");
            if actual_access_token_hash != *expected_access_token_hash {
                return Err(anyhow!("Invalid access token"));
            }
            tracing::trace!("after hash check");
        }

        Ok(claims.clone())
    }
}

pub async fn provider_metadata(url: &Url) -> AnyResult<ProviderMetadataWithLogout> {
    let issuer = IssuerUrl::from_url(url.clone());
    let config = ProviderMetadataWithLogout::discover_async(issuer, async_http_client).await?;
    Ok(config)
}
