mod authorization_code;
mod client_credentials;
mod handlers;
mod middleware;
mod token;
mod traits;

pub use authorization_code::{
    AuthorizationStore, ClientRegistry, RefreshTokenStore, authorize_approval_handler,
    authorize_handler,
};
pub use client_credentials::StaticClientValidator;
pub use handlers::{
    OAuthAppState, metadata_handler, oauth_token_handler, protected_resource_metadata_handler,
    register_handler,
};
pub use middleware::{AuthMiddlewareConfig, jwt_auth_middleware, legacy_auth_middleware};
pub use token::{JwtTokenIssuer, JwtTokenValidator};
pub use traits::{
    Claims, ClientInfo, CredentialValidator, TokenIssuer, TokenResponse, TokenValidator,
};

use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;

/// Configuration for the authentication system
#[derive(Clone)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub client_id: String,
    pub client_secret: String,
    pub token_expiration: Option<Duration>,
    /// How long refresh tokens are valid for (default 30 days)
    pub refresh_token_expiration: Duration,
    /// If true, invalidate token family on reuse; if false, just log warning
    pub strict_rotation: bool,
}

/// Complete OAuth service that combines validation, issuing, and verification
#[derive(Clone)]
pub struct OAuthService {
    credential_validator: Arc<dyn CredentialValidator + Send + Sync>,
    token_issuer: Arc<dyn TokenIssuer + Send + Sync>,
    token_validator: Arc<dyn TokenValidator + Send + Sync>,
    refresh_token_expiration: Duration,
    strict_rotation: bool,
}

impl OAuthService {
    pub fn new(config: AuthConfig) -> Self {
        let credential_validator = Arc::new(StaticClientValidator::new(
            config.client_id.clone(),
            config.client_secret.clone(),
        ));

        let token_issuer = Arc::new(JwtTokenIssuer::new(
            config.jwt_secret.clone(),
            config.token_expiration,
        ));

        let token_validator = Arc::new(JwtTokenValidator::new(config.jwt_secret.clone()));

        Self {
            credential_validator,
            token_issuer,
            token_validator,
            refresh_token_expiration: config.refresh_token_expiration,
            strict_rotation: config.strict_rotation,
        }
    }

    /// Get the configured refresh token expiration duration
    pub fn refresh_token_expiration(&self) -> Duration {
        self.refresh_token_expiration
    }

    /// Check if strict rotation mode is enabled
    pub fn strict_rotation(&self) -> bool {
        self.strict_rotation
    }

    // Delegate methods for easy access
    pub async fn validate_credentials(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<ClientInfo> {
        self.credential_validator
            .validate(client_id, client_secret)
            .await
    }

    pub fn issue_token(&self, client_id: &str) -> Result<TokenResponse> {
        self.token_issuer.issue_token(client_id, None)
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims> {
        self.token_validator.validate_token(token)
    }
}
