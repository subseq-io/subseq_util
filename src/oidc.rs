use anyhow::{anyhow, Result as AnyResult};
use openidconnect::{
    AccessToken,
    AccessTokenHash,
    AuthorizationCode,
    ClientId,
    ClientSecret,
    CsrfToken,
    IssuerUrl,
    Nonce,
    OAuth2TokenResponse,
    PkceCodeChallenge,
    PkceCodeVerifier,
    RefreshToken,
    RedirectUrl,
    Scope,
    TokenResponse,
};
use openidconnect::core::{
    CoreAuthenticationFlow,
    CoreClient,
    CoreIdToken,
    CoreIdTokenClaims,
    CoreProviderMetadata,
    CoreTokenResponse
};
use openidconnect::reqwest::async_http_client;
use serde::{Deserialize, Serialize};
use url::Url;


#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OidcToken {
    id_token: CoreIdToken,
    access_token: AccessToken,
    refresh_token: Option<RefreshToken>,
    nonce: Nonce
}

impl OidcToken {
    fn from_token_response(token: CoreTokenResponse, nonce: Nonce) -> AnyResult<Self> {
        Ok(Self {
            id_token: token.id_token().map(|t| t.clone())
                .ok_or_else(|| anyhow!("Server did not provide ID token!"))?,
            access_token: token.access_token().clone(),
            refresh_token: token.refresh_token().map(|t| t.clone()),
            nonce,
        })
    }
}

pub struct OidcCredentials {
    client_id: ClientId,
    client_secret: ClientSecret,
    redirect_url: RedirectUrl,
}

impl OidcCredentials {
    pub fn new<A: Into<String>, B: Into<String>, C: Into<String>, D: Into<String>>
            (client_id: A, client_secret: B, redirect_url: C) -> AnyResult<Self> {
        Ok(Self { client_id: ClientId::new(client_id.into()),
                  client_secret: ClientSecret::new(client_secret.into()),
                  redirect_url: RedirectUrl::new(redirect_url.into())? })
    }
}

pub struct IdentityProvider {
    client: CoreClient,
}

impl IdentityProvider {
    pub async fn new(oidc: &OidcCredentials, base_url: &str)
            -> AnyResult<Self>
    {
        let base_url = Url::parse(base_url)?;
        let config = provider_metadata(&base_url).await?;
        let client = CoreClient::from_provider_metadata(
            config,
            oidc.client_id.clone(),
            Some(oidc.client_secret.clone())
        ).set_redirect_uri(oidc.redirect_url.clone());

        Ok(Self { client })
    }

    pub fn login_oidc(&self, scopes: Vec<String>) -> (Url, CsrfToken, PkceCodeVerifier, Nonce) {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut auth_builder = self.client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            );
        for scope in scopes {
            auth_builder = auth_builder.add_scope(Scope::new(scope));
        }
        let (auth_url, csrf_token, nonce) = auth_builder
            .set_pkce_challenge(challenge)
            .url();
        (auth_url, csrf_token, verifier, nonce)
    }

    pub async fn token_oidc(
        &self, code: AuthorizationCode, verifier: PkceCodeVerifier, nonce: Nonce)
            -> AnyResult<OidcToken>
    {
        let token_response = self.client
            .exchange_code(code)
            .set_pkce_verifier(verifier)
            .request_async(async_http_client)
            .await?;
        let oidc_token = OidcToken::from_token_response(token_response, nonce)?;
        self.validate_token(&oidc_token)?;
        Ok(oidc_token)
    }

    pub fn validate_token(&self, token: &OidcToken) -> AnyResult<CoreIdTokenClaims>  {
        let verifier = self.client.id_token_verifier();
        let id_token = &token.id_token;
        let claims = id_token.claims(&verifier, &token.nonce)?;

        if let Some(expected_access_token_hash) = claims.access_token_hash() {
            let actual_access_token_hash = AccessTokenHash::from_token(
                &token.access_token,
                &id_token.signing_alg()?
            )?;
            if actual_access_token_hash != *expected_access_token_hash {
                return Err(anyhow!("Invalid access token"));
            }
        }

        Ok(claims.clone())
    }

}


pub async fn provider_metadata(url: &Url) -> AnyResult<CoreProviderMetadata>
{
    let issuer = IssuerUrl::from_url(url.clone());
    let config = CoreProviderMetadata::discover_async(
        issuer,
        async_http_client
    ).await?;
    Ok(config)
}
