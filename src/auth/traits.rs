use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

/// oauth 2.0 grant types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    AuthorizationCode,
    ClientCredentials,
    RefreshToken,
    /// catch-all for grant types we don't support
    /// Allows client registration to succeed even if client requests unsupported grants
    #[serde(other, skip_serializing)]
    Unsupported,
}

impl fmt::Display for GrantType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GrantType::AuthorizationCode => write!(f, "authorization_code"),
            GrantType::ClientCredentials => write!(f, "client_credentials"),
            GrantType::RefreshToken => write!(f, "refresh_token"),
            GrantType::Unsupported => write!(f, "unsupported"),
        }
    }
}

/// oauth 2.0 response types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseType {
    Code,
}

impl fmt::Display for ResponseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResponseType::Code => write!(f, "code"),
        }
    }
}

/// pkce code challenge methods
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodeChallengeMethod {
    #[default]
    S256,
}

impl fmt::Display for CodeChallengeMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodeChallengeMethod::S256 => write!(f, "S256"),
        }
    }
}

/// oauth 2.0 token types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenType {
    Bearer,
}

impl fmt::Display for TokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenType::Bearer => write!(f, "Bearer"),
        }
    }
}

// async_trait my beloved. this shit rocks

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub client_id: String,
    pub scopes: Vec<String>, // For future use
}

#[async_trait]
pub trait CredentialValidator {
    async fn validate(&self, client_id: &str, client_secret: &str) -> Result<ClientInfo>;
}

pub trait TokenIssuer {
    fn issue_token(
        &self,
        client_id: &str,
        custom_duration: Option<Duration>,
    ) -> Result<TokenResponse>;
}

pub trait TokenValidator {
    fn validate_token(&self, token: &str) -> Result<Claims>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: TokenType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>, // seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // Subject (client_id)
    pub iat: i64,    // Issued at
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>, // Expiration time
    pub jti: String, // JWT ID (unique identifier)
    pub iss: String, // Issuer
}
