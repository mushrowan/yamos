use super::authorization_code::{verify_pkce, AuthorizationStore, ClientRegistry};
use super::OAuthService;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    Form,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Combined OAuth state for all handlers
#[derive(Clone)]
pub struct OAuthAppState {
    pub oauth_service: Arc<OAuthService>,
    pub auth_store: Arc<AuthorizationStore>,
    pub client_registry: Arc<ClientRegistry>,
    pub base_url: String,
}

/// OAuth 2.0 token request (supports both grant types)
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    /// Client ID (required for both grant types)
    pub client_id: Option<String>,
    /// Client secret (required for client_credentials, optional for authorization_code with PKCE)
    pub client_secret: Option<String>,
    /// Authorization code (required for authorization_code grant)
    pub code: Option<String>,
    /// PKCE code verifier (required for authorization_code grant)
    pub code_verifier: Option<String>,
    /// Redirect URI (required for authorization_code grant)
    pub redirect_uri: Option<String>,
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

    match req.grant_type.as_str() {
        "authorization_code" => handle_authorization_code_grant(&state, &req).await,
        "client_credentials" => handle_client_credentials_grant(&state, &req).await,
        _ => error_response(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            Some("Supported grant types: authorization_code, client_credentials"),
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
            )
        }
    };

    let code_verifier = match &req.code_verifier {
        Some(v) => v,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("Missing required parameter: code_verifier"),
            )
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

    // Verify PKCE
    if !verify_pkce(code_verifier, &pending.code_challenge) {
        tracing::warn!("PKCE verification failed for client {}", pending.client_id);
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            Some("PKCE verification failed"),
        );
    }

    // Verify redirect_uri matches if provided
    if let Some(redirect_uri) = &req.redirect_uri {
        if redirect_uri != &pending.redirect_uri {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                Some("redirect_uri mismatch"),
            );
        }
    }

    // Issue token
    match state.oauth_service.issue_token(&pending.client_id) {
        Ok(token_response) => {
            tracing::info!(
                "Issued OAuth token via authorization_code for client: {}",
                pending.client_id
            );
            (StatusCode::OK, Json(token_response)).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to issue token: {}", e);
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                Some("Failed to issue token"),
            )
        }
    }
}

async fn handle_client_credentials_grant(state: &OAuthAppState, req: &TokenRequest) -> Response {
    let client_id = match &req.client_id {
        Some(id) => id,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("Missing required parameter: client_id"),
            )
        }
    };

    let client_secret = match &req.client_secret {
        Some(secret) => secret,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("Missing required parameter: client_secret"),
            )
        }
    };

    // Validate client credentials
    match state
        .oauth_service
        .validate_credentials(client_id, client_secret)
        .await
    {
        Ok(client_info) => {
            // Issue token
            match state.oauth_service.issue_token(&client_info.client_id) {
                Ok(token_response) => {
                    tracing::info!(
                        "Issued OAuth token via client_credentials for client: {}",
                        client_info.client_id
                    );
                    (StatusCode::OK, Json(token_response)).into_response()
                }
                Err(e) => {
                    tracing::error!("Failed to issue token: {}", e);
                    error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "server_error",
                        Some("Failed to issue token"),
                    )
                }
            }
        }
        Err(_) => {
            // Don't leak information about why validation failed
            error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                Some("Client authentication failed"),
            )
        }
    }
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
    // advertise authorization_code with PKCE (public clients)
    // client_credentials is still supported but not advertised to avoid confusion
    let metadata = AuthorizationServerMetadata {
        issuer: base_url.clone(),
        authorization_endpoint: Some(format!("{}/authorize", base_url)),
        token_endpoint: format!("{}/token", base_url),
        registration_endpoint: Some(format!("{}/register", base_url)),
        grant_types_supported: vec!["authorization_code".to_string()],
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
    pub grant_types: Option<Vec<String>>,
    pub redirect_uris: Option<Vec<String>>,
}

/// Dynamic Client Registration Response (RFC 7591)
#[derive(Debug, Serialize)]
pub struct ClientRegistrationResponse {
    pub client_id: String,
    pub client_secret: String,
    pub client_id_issued_at: i64,
    pub client_secret_expires_at: i64,
    pub grant_types: Vec<String>,
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

    // Validate grant types if provided
    let supported_grants = ["authorization_code", "client_credentials"];
    if let Some(ref grant_types) = req.grant_types {
        for gt in grant_types {
            if !supported_grants.contains(&gt.as_str()) {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_client_metadata",
                    Some("Supported grant types: authorization_code, client_credentials"),
                );
            }
        }
    }

    // Generate new client credentials
    use uuid::Uuid;
    let client_id = format!("mcp-client-{}", Uuid::new_v4());
    // For public clients using authorization_code with PKCE, secret is optional
    // but we generate one anyway for flexibility
    let client_secret = Uuid::new_v4().to_string();

    let grant_types = req
        .grant_types
        .unwrap_or_else(|| vec!["authorization_code".to_string()]);

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
