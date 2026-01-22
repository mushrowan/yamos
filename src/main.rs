mod auth;
mod couchdb;
mod server;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use rmcp::ServiceExt;
use server::YamosServer;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TransportMode {
    Stdio,
    Sse,
}

// could this use enums/groups so that we're not offering sse-only flags when using stdio transport? yep.
// do i care? no.
#[derive(Parser, Debug)]
#[command(name = "yamos")]
#[command(about = "yet another mcp obsidian server, for obsidian livesync via couchdb")]
struct Args {
    /// Transport mode to use
    #[arg(short, long, value_enum, env = "MCP_TRANSPORT", default_value = "sse")]
    transport: TransportMode,

    /// Host to bind to (SSE mode only)
    #[arg(long, env = "MCP_HOST", default_value = "localhost")]
    host: String,

    /// Port to bind to (SSE mode only)
    #[arg(short, long, env = "MCP_PORT", default_value = "3000")]
    port: u16,

    /// CouchDB URL
    #[arg(long, env = "COUCHDB_URL", default_value = "http://localhost:5984")]
    couchdb_url: String,

    /// CouchDB database name
    #[arg(long, env = "COUCHDB_DATABASE", default_value = "obsidian")]
    couchdb_database: String,

    /// CouchDB username
    #[arg(long, env = "COUCHDB_USER")]
    couchdb_user: String,

    /// CouchDB password
    #[arg(long, env = "COUCHDB_PASSWORD")]
    couchdb_password: String,

    /// Enable OAuth 2.0 authentication (disables legacy bearer token auth)
    #[arg(long, env = "OAUTH_ENABLED", default_value = "false")]
    oauth_enabled: bool,

    /// JWT signing secret for OAuth tokens
    #[arg(long, env = "OAUTH_JWT_SECRET")]
    oauth_jwt_secret: Option<String>,

    /// Access token expiration in seconds (0 = no expiration)
    #[arg(long, env = "OAUTH_TOKEN_EXPIRATION", default_value = "3600")]
    oauth_token_expiration: u64,

    /// Refresh token expiration in seconds (default 30 days)
    #[arg(
        long,
        env = "OAUTH_REFRESH_TOKEN_EXPIRATION",
        default_value = "2592000"
    )]
    oauth_refresh_token_expiration: u64,

    /// Strict rotation: invalidate token family on refresh token reuse (default: just log)
    #[arg(long, env = "OAUTH_STRICT_ROTATION", default_value = "false")]
    oauth_strict_rotation: bool,

    /// OAuth client ID
    #[arg(long, env = "OAUTH_CLIENT_ID")]
    oauth_client_id: Option<String>,

    /// OAuth client secret
    #[arg(long, env = "OAUTH_CLIENT_SECRET")]
    oauth_client_secret: Option<String>,

    /// Authentication token for bearer SSE mode (OAuth is better)
    #[arg(long, env = "MCP_AUTH_TOKEN")]
    auth_token: Option<String>,

    /// Public base URL for OAuth metadata (e.g., https://your-domain.com)
    /// If not set, defaults to http://HOST:PORT
    #[arg(long, env = "PUBLIC_URL")]
    public_url: Option<String>,

    /// Rate limit: requests per second per IP
    #[arg(long, env = "RATE_LIMIT_PER_SECOND", default_value = "10")]
    rate_limit_per_second: u64,

    /// Rate limit: burst size (max requests before limiting kicks in)
    #[arg(long, env = "RATE_LIMIT_BURST", default_value = "100")]
    rate_limit_burst: u32,

    /// Base path for all routes, for hosting at a subpath
    #[arg(long, env = "BASE_PATH", default_value = "")]
    base_path: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables from .env file if present
    let _ = dotenvy::dotenv();

    let args = Args::parse();

    // Initialise logging to stderr (so it doesn't interfere with stdio transport)
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "yamos=info".into()),
        )
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!(
        "Connecting to CouchDB at {}/{}",
        args.couchdb_url,
        args.couchdb_database
    );

    // Create CouchDB client
    let db = couchdb::CouchDbClient::new(
        &args.couchdb_url,
        &args.couchdb_database,
        &args.couchdb_user,
        &args.couchdb_password,
    )?;

    // Test connection
    db.test_connection().await?;
    tracing::info!("Successfully connected to CouchDB");

    // Create the MCP server
    let server = YamosServer::new(db);

    match args.transport {
        TransportMode::Stdio => {
            tracing::info!("Starting in stdio mode");
            let service = server.serve(rmcp::transport::stdio()).await?;
            service.waiting().await?;
        }
        TransportMode::Sse => {
            tracing::info!("Starting in SSE mode on {}:{}", args.host, args.port);

            let auth_mode = determine_auth_mode(&args)?;

            let rate_limit = RateLimitConfig {
                per_second: args.rate_limit_per_second,
                burst: args.rate_limit_burst,
            };

            // normalise base_path: ensure it starts with / if non-empty, no trailing slash
            let base_path = if args.base_path.is_empty() {
                String::new()
            } else {
                let p = args.base_path.trim_matches('/');
                format!("/{}", p)
            };

            match auth_mode {
                AuthMode::OAuth(config) => {
                    tracing::info!("OAuth 2.0 authentication enabled");
                    run_sse_server_with_oauth(
                        server,
                        &args.host,
                        args.port,
                        config,
                        args.public_url.as_deref(),
                        &rate_limit,
                        &base_path,
                    )
                    .await?;
                }
                AuthMode::Legacy(token) => {
                    tracing::info!(
                        "Bearer token authentication enabled (consider migrating to OAuth)"
                    );
                    run_sse_server_legacy(
                        server,
                        &args.host,
                        args.port,
                        token,
                        &rate_limit,
                        &base_path,
                    )
                    .await?;
                }
                AuthMode::None => {
                    tracing::warn!(
                        "WARNING: No authentication enabled. Server is publicly accessible!"
                    );
                    run_sse_server_no_auth(server, &args.host, args.port, &rate_limit, &base_path)
                        .await?;
                }
            }
        }
    }

    Ok(())
}

enum AuthMode {
    OAuth(auth::AuthConfig),
    Legacy(String),
    None,
}

struct RateLimitConfig {
    per_second: u64,
    burst: u32,
}

fn determine_auth_mode(args: &Args) -> Result<AuthMode> {
    if args.oauth_enabled {
        let jwt_secret = args
            .oauth_jwt_secret
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("OAUTH_JWT_SECRET required when OAuth is enabled"))?;

        let client_id = args
            .oauth_client_id
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("OAUTH_CLIENT_ID required when OAuth is enabled"))?;

        let client_secret = args
            .oauth_client_secret
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("OAUTH_CLIENT_SECRET required when OAuth is enabled"))?;

        Ok(AuthMode::OAuth(auth::AuthConfig {
            jwt_secret: jwt_secret.clone(),
            client_id: client_id.clone(),
            client_secret: client_secret.clone(),
            token_expiration: if args.oauth_token_expiration == 0 {
                None
            } else {
                Some(std::time::Duration::from_secs(args.oauth_token_expiration))
            },
            refresh_token_expiration: std::time::Duration::from_secs(
                args.oauth_refresh_token_expiration,
            ),
            strict_rotation: args.oauth_strict_rotation,
        }))
    } else if let Some(token) = &args.auth_token {
        Ok(AuthMode::Legacy(token.clone()))
    } else {
        Ok(AuthMode::None)
    }
}

async fn run_sse_server_with_oauth(
    server: YamosServer,
    host: &str,
    port: u16,
    config: auth::AuthConfig,
    public_url: Option<&str>,
    rate_limit: &RateLimitConfig,
    base_path: &str,
) -> Result<()> {
    use axum::{
        Router, middleware,
        routing::{get, post},
    };
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::tower::{
        StreamableHttpServerConfig, StreamableHttpService,
    };
    use std::net::SocketAddr;
    use tower_governor::{
        GovernorLayer, governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor,
    };

    let bind_addr = format!("{}:{}", host, port);

    // base_url includes the base_path for OAuth metadata URLs
    let base_url = public_url
        .map(|url| format!("{}{}", url.trim_end_matches('/'), base_path))
        .unwrap_or_else(|| format!("http://{}:{}{}", host, port, base_path));

    tracing::info!("MCP server listening on {}", bind_addr);
    if let Some(public) = public_url {
        tracing::info!("Public URL: {}", public);
    }
    tracing::info!("MCP endpoint: {}/", base_url);
    tracing::info!(
        "Protected resource metadata: {}/.well-known/oauth-protected-resource",
        base_url
    );
    tracing::info!(
        "Authorization server metadata: {}/.well-known/oauth-authorization-server",
        base_url
    );
    tracing::info!("Token endpoint: {}/token", base_url);
    tracing::info!("Registration endpoint: {}/register", base_url);

    let session_manager = Arc::new(LocalSessionManager::default());

    let http_service = StreamableHttpService::new(
        move || Ok(server.clone()),
        session_manager,
        StreamableHttpServerConfig::default(),
    );

    let oauth_service = Arc::new(auth::OAuthService::new(config));
    let auth_store = Arc::new(auth::AuthorizationStore::new());
    let refresh_token_store = Arc::new(auth::RefreshTokenStore::new());
    let client_registry = Arc::new(auth::ClientRegistry::new());

    // Combined OAuth state for all handlers
    let oauth_state = auth::OAuthAppState {
        oauth_service: oauth_service.clone(),
        auth_store: auth_store.clone(),
        refresh_token_store: refresh_token_store.clone(),
        client_registry: client_registry.clone(),
        base_url: base_url.clone(),
    };

    // Rate limiting - configurable via RATE_LIMIT_PER_SECOND and RATE_LIMIT_BURST
    // SmartIpKeyExtractor checks x-forwarded-for and friends before falling back to peer ip,
    // so this works both behind cloudflare/nginx/whatever and when running locally
    tracing::info!(
        "Rate limiting: {} req/sec, burst size {}",
        rate_limit.per_second,
        rate_limit.burst
    );
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_second(rate_limit.per_second)
            .burst_size(rate_limit.burst)
            .finish()
            .expect("Failed to build rate limiter config"),
    );
    let governor_limiter = governor_conf.limiter().clone();
    let rate_limit_layer = GovernorLayer::new(governor_conf);

    // Stricter rate limiting for auth endpoints: half the normal rate
    let auth_governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_second(rate_limit.per_second / 2)
            .burst_size(rate_limit.burst / 3)
            .finish()
            .expect("Failed to build auth rate limiter config"),
    );
    let auth_rate_limit_layer = GovernorLayer::new(auth_governor_conf);

    // public oauth endpoints - no auth required (that's the whole point)
    // Rate-limited endpoints for auth (stricter limits on token/register)
    let rate_limited_auth_routes = Router::new()
        .route("/token", post(auth::oauth_token_handler))
        .route("/register", post(auth::register_handler))
        .layer(auth_rate_limit_layer)
        .with_state(oauth_state.clone());

    // Standard rate limiting for other OAuth endpoints
    let oauth_routes = Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(auth::protected_resource_metadata_handler),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(auth::metadata_handler),
        )
        .route("/authorize", get(auth::authorize_handler))
        .route("/authorize/callback", get(auth::authorize_approval_handler))
        .with_state(oauth_state);

    // Start background task to clean up rate limiter state
    tokio::spawn({
        let limiter = governor_limiter;
        async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                limiter.retain_recent();
            }
        }
    });

    // Start background task to clean up expired refresh tokens
    tokio::spawn({
        let store = refresh_token_store.clone();
        async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(300)).await; // every 5 mins
                store.cleanup_expired().await;
            }
        }
    });

    let auth_config = auth::AuthMiddlewareConfig {
        oauth_service: oauth_service.clone(),
        base_url: base_url.clone(),
    };

    // protected routes - jwt required, with rate limiting
    let protected_routes = Router::new()
        .route_service("/", http_service)
        .layer(middleware::from_fn_with_state(
            auth_config,
            auth::jwt_auth_middleware,
        ))
        .layer(rate_limit_layer);

    let all_routes = oauth_routes
        .merge(rate_limited_auth_routes)
        .merge(protected_routes);

    // nest under base_path if set
    let app = if base_path.is_empty() {
        all_routes
    } else {
        Router::new().nest(base_path, all_routes)
    };

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!("Server ready at {}", base_url);

    // into_make_service_with_connect_info gives us the peer ip for rate limiting fallback
    // (SmartIpKeyExtractor checks headers first, but falls back to this if no proxy headers)
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

async fn run_sse_server_legacy(
    server: YamosServer,
    host: &str,
    port: u16,
    token: String,
    rate_limit: &RateLimitConfig,
    base_path: &str,
) -> Result<()> {
    use axum::{Router, middleware};
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::tower::{
        StreamableHttpServerConfig, StreamableHttpService,
    };
    use std::net::SocketAddr;
    use tower_governor::{
        GovernorLayer, governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor,
    };

    let bind_addr = format!("{}:{}", host, port);
    let base_url = format!("http://{}:{}{}", host, port, base_path);

    tracing::info!("MCP server listening on {}", bind_addr);
    tracing::info!(
        "Rate limiting: {} req/sec, burst size {}",
        rate_limit.per_second,
        rate_limit.burst
    );

    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_second(rate_limit.per_second)
            .burst_size(rate_limit.burst)
            .finish()
            .expect("Failed to build rate limiter config"),
    );
    let rate_limit_layer = GovernorLayer::new(governor_conf);

    let session_manager = Arc::new(LocalSessionManager::default());

    let http_service = StreamableHttpService::new(
        move || Ok(server.clone()),
        session_manager,
        StreamableHttpServerConfig::default(),
    );

    let token_arc = Arc::new(token);
    let routes = Router::new()
        .route_service("/", http_service)
        .layer(middleware::from_fn(move |req, next| {
            auth::legacy_auth_middleware(req, next, token_arc.clone())
        }))
        .layer(rate_limit_layer);

    let app = if base_path.is_empty() {
        routes
    } else {
        Router::new().nest(base_path, routes)
    };

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!("Server ready at {}", base_url);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

async fn run_sse_server_no_auth(
    server: YamosServer,
    host: &str,
    port: u16,
    rate_limit: &RateLimitConfig,
    base_path: &str,
) -> Result<()> {
    use axum::Router;
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::tower::{
        StreamableHttpServerConfig, StreamableHttpService,
    };
    use std::net::SocketAddr;
    use tower_governor::{
        GovernorLayer, governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor,
    };

    let bind_addr = format!("{}:{}", host, port);
    let base_url = format!("http://{}:{}{}", host, port, base_path);

    tracing::info!("MCP server listening on {}", bind_addr);
    tracing::info!(
        "Rate limiting: {} req/sec, burst size {}",
        rate_limit.per_second,
        rate_limit.burst
    );

    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_second(rate_limit.per_second)
            .burst_size(rate_limit.burst)
            .finish()
            .expect("Failed to build rate limiter config"),
    );
    let rate_limit_layer = GovernorLayer::new(governor_conf);

    let session_manager = Arc::new(LocalSessionManager::default());

    let http_service = StreamableHttpService::new(
        move || Ok(server.clone()),
        session_manager,
        StreamableHttpServerConfig::default(),
    );

    let routes = Router::new()
        .route_service("/", http_service)
        .layer(rate_limit_layer);

    let app = if base_path.is_empty() {
        routes
    } else {
        Router::new().nest(base_path, routes)
    };

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!("Server ready at {}", base_url);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
