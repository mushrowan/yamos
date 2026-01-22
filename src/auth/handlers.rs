use super::OAuthService;
use super::authorization_code::{
    AuthorizationStore, ClientRegistry, RefreshTokenStore, RefreshTokenValidation, verify_pkce,
};
use super::traits::GrantType;
use axum::{
    Form,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Combined OAuth state for all handlers
#[derive(Clone)]
pub struct OAuthAppState {
    pub oauth_service: Arc<OAuthService>,
    pub auth_store: Arc<AuthorizationStore>,
    pub refresh_token_store: Arc<RefreshTokenStore>,
    pub client_registry: Arc<ClientRegistry>,
    pub base_url: String,
}

/// OAuth 2.0 token request (supports all grant types)
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: GrantType,
    /// Client ID (required for client_credentials, optional for others)
    pub client_id: Option<String>,
    /// Client secret (required for client_credentials, optional for authorization_code with PKCE)
    pub client_secret: Option<String>,
    /// Authorization code (required for authorization_code grant)
    pub code: Option<String>,
    /// PKCE code verifier (required for authorization_code grant)
    pub code_verifier: Option<String>,
    /// Redirect URI (required for authorization_code grant)
    pub redirect_uri: Option<String>,
    /// Refresh token (required for refresh_token grant)
    pub refresh_token: Option<String>,
}

/// OAuth 2.0 error response
#[derive(Debug, serde::Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
}

/// Handler for POST /token
pub async fn oauth_token_handler(
    State(state): State<OAuthAppState>,
    Form(req): Form<TokenRequest>,
) -> Response {
    tracing::info!("Token request: grant_type={}", req.grant_type);

    match req.grant_type {
        GrantType::AuthorizationCode => handle_authorization_code_grant(&state, &req).await,
        GrantType::ClientCredentials => handle_client_credentials_grant(&state, &req).await,
        GrantType::RefreshToken => handle_refresh_token_grant(&state, &req).await,
        GrantType::Unsupported => error_response(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            Some("The grant type is not supported by this server"),
        ),
    }
}

async fn handle_authorization_code_grant(state: &OAuthAppState, req: &TokenRequest) -> Response {
    // clean up expired authorisations (also done in authorize_handler, but oh well)
    state.auth_store.cleanup_expired().await;

    // validate required parameters
    let code = match &req.code {
        Some(c) => c,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("Missing required parameter: code"),
            );
        }
    };

    let code_verifier = match &req.code_verifier {
        Some(v) => v,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("Missing required parameter: code_verifier"),
            );
        }
    };

    // Look up the authorization code
    let pending = match state.auth_store.take_pending(code).await {
        Some(p) => p,
        None => {
            tracing::warn!("Invalid or expired authorization code");
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                Some("Invalid or expired authorization code"),
            );
        }
    };

    // Verify redirect_uri matches (must match the one from the authorization request)
    let redirect_uri = match &req.redirect_uri {
        Some(uri) => uri,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("Missing required parameter: redirect_uri"),
            );
        }
    };

    if redirect_uri != &pending.redirect_uri {
        tracing::warn!(
            "redirect_uri mismatch for client {}: expected '{}', got '{}'",
            pending.client_id,
            pending.redirect_uri,
            redirect_uri
        );
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            Some("redirect_uri mismatch"),
        );
    }

    // Verify PKCE
    if !verify_pkce(code_verifier, &pending.code_challenge) {
        tracing::warn!("PKCE verification failed for client {}", pending.client_id);
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            Some("PKCE verification failed"),
        );
    }

    // Issue access token
    let mut token_response = match state.oauth_service.issue_token(&pending.client_id) {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!("Failed to issue token: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                Some("Failed to issue token"),
            );
        }
    };

    // Issue refresh token
    let refresh_token_id = Uuid::new_v4().to_string();
    let family_id = Uuid::new_v4().to_string();
    let refresh_expiration = state.oauth_service.refresh_token_expiration();

    state
        .refresh_token_store
        .store(
            refresh_token_id.clone(),
            family_id.clone(),
            pending.client_id.clone(),
            refresh_expiration,
        )
        .await;

    token_response.refresh_token = Some(refresh_token_id);

    tracing::info!(
        "Issued OAuth token via authorization_code for client: {} (family: {})",
        pending.client_id,
        family_id
    );

    (StatusCode::OK, Json(token_response)).into_response()
}

async fn handle_client_credentials_grant(state: &OAuthAppState, req: &TokenRequest) -> Response {
    let client_id = match &req.client_id {
        Some(id) => id,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("Missing required parameter: client_id"),
            );
        }
    };

    let client_secret = match &req.client_secret {
        Some(secret) => secret,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("Missing required parameter: client_secret"),
            );
        }
    };

    // Validate client credentials
    let client_info = match state
        .oauth_service
        .validate_credentials(client_id, client_secret)
        .await
    {
        Ok(info) => info,
        Err(_) => {
            // Don't leak information about why validation failed
            return error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                Some("Client authentication failed"),
            );
        }
    };

    // Issue access token
    let mut token_response = match state.oauth_service.issue_token(&client_info.client_id) {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!("Failed to issue token: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                Some("Failed to issue token"),
            );
        }
    };

    // Issue refresh token
    let refresh_token_id = Uuid::new_v4().to_string();
    let family_id = Uuid::new_v4().to_string();
    let refresh_expiration = state.oauth_service.refresh_token_expiration();

    state
        .refresh_token_store
        .store(
            refresh_token_id.clone(),
            family_id.clone(),
            client_info.client_id.clone(),
            refresh_expiration,
        )
        .await;

    token_response.refresh_token = Some(refresh_token_id);

    tracing::info!(
        "Issued OAuth token via client_credentials for client: {} (family: {})",
        client_info.client_id,
        family_id
    );

    (StatusCode::OK, Json(token_response)).into_response()
}

async fn handle_refresh_token_grant(state: &OAuthAppState, req: &TokenRequest) -> Response {
    // clean up expired tokens periodically
    state.refresh_token_store.cleanup_expired().await;

    let refresh_token = match &req.refresh_token {
        Some(t) => t,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("Missing required parameter: refresh_token"),
            );
        }
    };

    // Validate the refresh token
    let (client_id, family_id) = match state.refresh_token_store.validate(refresh_token).await {
        RefreshTokenValidation::Valid(entry) => (entry.client_id, entry.family_id),

        RefreshTokenValidation::GracePeriod {
            new_token_id,
            entry,
        } => {
            // Token was already rotated but we're within grace period
            // Return the new token that was issued
            tracing::debug!(
                "Refresh token used within grace period, returning previously issued token for family {}",
                entry.family_id
            );

            // Issue a fresh access token for the same client
            let mut token_response = match state.oauth_service.issue_token(&entry.client_id) {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::error!("Failed to issue token: {}", e);
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "server_error",
                        Some("Failed to issue token"),
                    );
                }
            };

            // Return the new refresh token that was already created
            token_response.refresh_token = Some(new_token_id);

            tracing::info!(
                "Issued OAuth token via refresh_token (grace period) for client: {}",
                entry.client_id
            );

            return (StatusCode::OK, Json(token_response)).into_response();
        }

        RefreshTokenValidation::Reused { family_id } => {
            tracing::warn!(
                "Refresh token reuse detected for family {}! Potential token theft.",
                family_id
            );

            // If strict rotation is enabled, invalidate the entire token family
            if state.oauth_service.strict_rotation() {
                state
                    .refresh_token_store
                    .invalidate_family(&family_id)
                    .await;
                tracing::warn!(
                    "Strict rotation enabled: invalidated all tokens in family {}",
                    family_id
                );
            }

            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                Some("Refresh token has already been used"),
            );
        }

        RefreshTokenValidation::NotFound => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                Some("Invalid refresh token"),
            );
        }

        RefreshTokenValidation::Expired => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                Some("Refresh token has expired"),
            );
        }
    };

    // Generate new refresh token (rotation)
    let new_refresh_token_id = Uuid::new_v4().to_string();
    let refresh_expiration = state.oauth_service.refresh_token_expiration();

    // Rotate: mark old token as used, create new one in same family
    state
        .refresh_token_store
        .rotate(refresh_token, &new_refresh_token_id)
        .await;

    // Store the new refresh token
    state
        .refresh_token_store
        .store(
            new_refresh_token_id.clone(),
            family_id.clone(),
            client_id.clone(),
            refresh_expiration,
        )
        .await;

    // Issue new access token
    let mut token_response = match state.oauth_service.issue_token(&client_id) {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!("Failed to issue token: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                Some("Failed to issue token"),
            );
        }
    };

    token_response.refresh_token = Some(new_refresh_token_id);

    tracing::info!(
        "Issued OAuth token via refresh_token for client: {} (family: {})",
        client_id,
        family_id
    );

    (StatusCode::OK, Json(token_response)).into_response()
}

fn error_response(status: StatusCode, error: &str, description: Option<&str>) -> Response {
    let error_resp = ErrorResponse {
        error: error.to_string(),
        error_description: description.map(|s| s.to_string()),
    };
    (status, Json(error_resp)).into_response()
}

/// Protected resource metadata (RFC 9728) - tells clients where to authenticate
#[derive(Debug, Serialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
}

/// First thing MCP clients hit to figure out how to auth
pub async fn protected_resource_metadata_handler(State(state): State<OAuthAppState>) -> Response {
    let metadata = ProtectedResourceMetadata {
        resource: state.base_url.clone(),
        authorization_servers: vec![state.base_url], // we're our own auth server
    };
    (StatusCode::OK, Json(metadata)).into_response()
}

/// Auth server metadata (RFC 8414)
#[derive(Debug, Serialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: String,
    pub registration_endpoint: Option<String>,
    pub grant_types_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

/// Tells clients what auth methods we support
pub async fn metadata_handler(State(state): State<OAuthAppState>) -> Response {
    let base_url = &state.base_url;
    // advertise authorization_code with PKCE (public clients) and refresh_token
    // client_credentials is still supported but not advertised to avoid confusion
    let metadata = AuthorizationServerMetadata {
        issuer: base_url.clone(),
        authorization_endpoint: Some(format!("{}/authorize", base_url)),
        token_endpoint: format!("{}/token", base_url),
        registration_endpoint: Some(format!("{}/register", base_url)),
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        token_endpoint_auth_methods_supported: vec!["none".to_string()],
        response_types_supported: vec!["code".to_string()],
        code_challenge_methods_supported: Some(vec!["S256".to_string()]),
    };

    tracing::info!("Serving authorization server metadata");

    let mut headers = HeaderMap::new();
    headers.insert("MCP-Protocol-Version", "2025-06-18".parse().unwrap());

    (StatusCode::OK, headers, Json(metadata)).into_response()
}

/// Dynamic Client Registration Request (RFC 7591)
#[derive(Debug, Deserialize)]
pub struct ClientRegistrationRequest {
    pub client_name: Option<String>,
    pub grant_types: Option<Vec<GrantType>>,
    pub redirect_uris: Option<Vec<String>>,
}

/// Dynamic Client Registration Response (RFC 7591)
#[derive(Debug, Serialize)]
pub struct ClientRegistrationResponse {
    pub client_id: String,
    pub client_secret: String,
    pub client_id_issued_at: i64,
    pub client_secret_expires_at: i64,
    pub grant_types: Vec<GrantType>,
}

/// Dynamic client registration (RFC 7591)
/// NB: credentials aren't persisted - they won't survive a restart
pub async fn register_handler(
    State(state): State<OAuthAppState>,
    Json(req): Json<ClientRegistrationRequest>,
) -> Response {
    tracing::info!(
        "dynamic client registration request: client_name={:?}, grant_types={:?}, redirect_uris={:?}",
        req.client_name,
        req.grant_types,
        req.redirect_uris
    );

    // Generate new client credentials
    let client_id = format!("mcp-client-{}", Uuid::new_v4());
    // For public clients using authorization_code with PKCE, secret is optional
    // but we generate one anyway for flexibility
    let client_secret = Uuid::new_v4().to_string();

    // filter out unsupported grant types
    let grant_types: Vec<GrantType> = req
        .grant_types
        .unwrap_or_else(|| vec![GrantType::AuthorizationCode])
        .into_iter()
        .filter(|g| !matches!(g, GrantType::Unsupported))
        .collect();
    // default to authorization_code if client only requested unsupported grants
    let grant_types = if grant_types.is_empty() {
        vec![GrantType::AuthorizationCode]
    } else {
        grant_types
    };

    // register the client's redirect URIs so they can be validated later
    let redirect_uris = req.redirect_uris.clone().unwrap_or_default();
    if !redirect_uris.is_empty() {
        state
            .client_registry
            .register(client_id.clone(), redirect_uris)
            .await;
    }

    let response = ClientRegistrationResponse {
        client_id: client_id.clone(),
        client_secret,
        client_id_issued_at: chrono::Utc::now().timestamp(),
        client_secret_expires_at: 0, // Never expires in this implementation
        grant_types,
    };

    tracing::info!(
        "Dynamic client registration: Generated credentials for client '{}'",
        client_id
    );

    (StatusCode::CREATED, Json(response)).into_response()
}
