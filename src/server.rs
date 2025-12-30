use crate::couchdb::CouchDbClient;
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars, tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler,
};
use serde::Deserialize;
use std::borrow::Cow;

/// Validate a note path to prevent path traversal and ensure it's a valid Obsidian note path.
fn validate_note_path(path: &str) -> Result<(), McpError> {
    let check = |cond: bool, msg: &str| if cond { Err(mcp_error(msg)) } else { Ok(()) };

    check(path.is_empty(), "Note path cannot be empty")?;
    check(!path.ends_with(".md"), "Note path must end with .md")?;
    check(path.contains(".."), "Note path cannot contain '..'")?;
    check(path.starts_with('/'), "Note path cannot start with '/'")?;
    check(path.contains('\0'), "Note path cannot contain null bytes")?;

    // Allowed: alphanumeric, space, hyphen, underscore, dot, slash, parentheses
    let invalid_char = path
        .chars()
        .find(|c| !c.is_alphanumeric() && !" -_./()'".contains(*c));

    if let Some(c) = invalid_char {
        return Err(mcp_error(format!("Note path contains invalid character: '{c}'")));
    }

    Ok(())
}

#[derive(Clone)]
pub struct YamosServer {
    db: CouchDbClient,
    tool_router: ToolRouter<Self>,
}

// Request types for tools with parameters
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListNotesRequest {
    #[schemars(description = "Optional path prefix to filter notes (e.g. 'Projects/')")]
    pub prefix: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReadNoteRequest {
    #[schemars(description = "Path to the note (e.g. 'Todo.md' or 'Projects/myproject.md')")]
    pub path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WriteNoteRequest {
    #[schemars(description = "Path to the note (e.g. 'Todo.md' or 'Projects/myproject.md')")]
    pub path: String,
    #[schemars(description = "Content to write to the note")]
    pub content: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AppendNoteRequest {
    #[schemars(description = "Path to the note to append to")]
    pub path: String,
    #[schemars(description = "Content to append (will be added on a new line)")]
    pub content: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DeleteNoteRequest {
    #[schemars(description = "Path to the note to delete")]
    pub path: String,
}

fn mcp_error(msg: impl Into<String>) -> McpError {
    McpError {
        code: ErrorCode::INTERNAL_ERROR,
        message: Cow::Owned(msg.into()),
        data: None,
    }
}

#[tool_router]
impl YamosServer {
    pub fn new(db: CouchDbClient) -> Self {
        Self {
            db,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "List all notes in the Obsidian vault, optionally filtered by path prefix"
    )]
    async fn list_notes(
        &self,
        Parameters(req): Parameters<ListNotesRequest>,
    ) -> Result<CallToolResult, McpError> {
        let notes = self
            .db
            .list_notes()
            .await
            .map_err(|e| mcp_error(e.to_string()))?;

        let filtered: Vec<_> = match &req.prefix {
            Some(prefix) => notes
                .into_iter()
                .filter(|n| n.starts_with(prefix))
                .collect(),
            None => notes,
        };

        let result = filtered.join("\n");
        Ok(CallToolResult::success(vec![Content::text(result)]))
    }

    #[tool(description = "Read the content of a note from the Obsidian vault")]
    async fn read_note(
        &self,
        Parameters(req): Parameters<ReadNoteRequest>,
    ) -> Result<CallToolResult, McpError> {
        validate_note_path(&req.path)?;

        let doc = self
            .db
            .get_note(&req.path)
            .await
            .map_err(|e| mcp_error(e.to_string()))?;

        let content = self
            .db
            .decode_content(&doc)
            .await
            .map_err(|e| mcp_error(e.to_string()))?;

        Ok(CallToolResult::success(vec![Content::text(content)]))
    }

    #[tool(description = "Create or update a note in the Obsidian vault")]
    async fn write_note(
        &self,
        Parameters(req): Parameters<WriteNoteRequest>,
    ) -> Result<CallToolResult, McpError> {
        validate_note_path(&req.path)?;

        self.db
            .save_note(&req.path, &req.content)
            .await
            .map_err(|e| mcp_error(e.to_string()))?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Successfully wrote to {}",
            req.path
        ))]))
    }

    #[tool(description = "Append content to an existing note (adds a newline before the content)")]
    async fn append_to_note(
        &self,
        Parameters(req): Parameters<AppendNoteRequest>,
    ) -> Result<CallToolResult, McpError> {
        validate_note_path(&req.path)?;

        self.db
            .append_to_note(&req.path, &req.content)
            .await
            .map_err(|e| mcp_error(e.to_string()))?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Successfully appended to {}",
            req.path
        ))]))
    }

    #[tool(description = "Delete a note from the Obsidian vault")]
    async fn delete_note(
        &self,
        Parameters(req): Parameters<DeleteNoteRequest>,
    ) -> Result<CallToolResult, McpError> {
        validate_note_path(&req.path)?;

        self.db
            .delete_note(&req.path)
            .await
            .map_err(|e| mcp_error(e.to_string()))?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Successfully deleted {}",
            req.path
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for YamosServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "Obsidian vault access via CouchDB/LiveSync. Use tools to list, read, write, append to, or delete notes.".to_string(),
            ),
        }
    }
}
