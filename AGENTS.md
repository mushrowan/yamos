# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

YAMOS (Yet Another MCP Obsidian Server) is a Rust MCP server that enables AI models to read/write Obsidian vault notes stored in CouchDB via Obsidian LiveSync. It supports SSE (web) and stdio (desktop) transport modes with OAuth 2.0 authentication.

## Build & Development Commands

```bash
# Development (nix users)
nix develop                              # Enter dev shell
cargo run -- --transport sse             # Run SSE mode with debug logging
cargo run -- --transport stdio           # Run stdio mode

# Development (non-nix)
cargo build --release
RUST_LOG=debug ./target/release/yamos --transport sse

# Testing & checks
cargo test
cargo clippy --all-targets -- --deny warnings
cargo fmt --check

# Nix-specific
nix build                                # Build release binary
nix flake check                          # Run all checks (clippy, fmt, build)
```

## Architecture

### Source Structure

```
src/
├── main.rs       # Entry point, CLI args (clap), transport/auth mode selection
├── server.rs     # MCP tool definitions using rmcp #[tool_router] macro
├── couchdb.rs    # CouchDB client, LiveSync chunked document handling
└── auth/
    ├── mod.rs              # OAuthService facade composing all auth components
    ├── traits.rs           # Abstract traits (CredentialValidator, TokenIssuer, etc.)
    ├── token.rs            # JWT token issuing/validation (HS256)
    ├── middleware.rs       # Axum middleware for JWT and legacy bearer auth
    ├── handlers.rs         # OAuth HTTP endpoints (/.well-known/*, /authorize, /token)
    ├── authorization_code.rs  # Authorization code grant + PKCE
    └── client_credentials.rs  # Client credentials grant
```

### Key Patterns

**MCP Tools**: Defined in `server.rs` using `#[tool_router]` and `#[tool]` macros from rmcp. Each tool has JSON schema validation via schemars.

**LiveSync Document Format**: Notes are stored as chunked documents in CouchDB:
- Main document (`NoteDoc`) contains metadata + `children` array of chunk IDs
- Each chunk (`LeafDoc`, ~32 bytes) stored separately with ID format `h:xxxxx`
- Writing: save chunks first, then parent document, then delete old chunks

**Auth Modes** (determined in `main.rs:determine_auth_mode()`):
1. OAuth 2.0 with JWT (recommended) - supports authorization code + PKCE and client credentials
2. Legacy bearer token - static token comparison
3. No auth - rate limiting only

**Transport Modes**:
- SSE: Axum HTTP server with rate limiting (`tower_governor`)
- Stdio: Direct rmcp transport, no HTTP/auth

### Critical Behaviors

- Path validation in `server.rs:validate_note_path()` prevents traversal attacks
- Batch operations use partial success - failures don't stop other items
- Soft-delete pattern: sets `deleted: true` (LiveSync compatible)
- In-memory auth state: credentials don't persist across restarts

## Configuration

All config via CLI flags or environment variables. Key ones:
- `COUCHDB_URL`, `COUCHDB_DATABASE`, `COUCHDB_USER`, `COUCHDB_PASSWORD`
- `MCP_TRANSPORT` (sse|stdio), `MCP_HOST`, `MCP_PORT`
- `OAUTH_ENABLED`, `OAUTH_JWT_SECRET`, `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`
- `PUBLIC_URL` (required for OAuth metadata endpoints)

See `.env.example` for full list.

## NixOS Module

The flake exports `nixosModules.default` for deployment. Configure via `services.yamos.settings` (converted to env vars) and `services.yamos.environmentFile` for secrets.
