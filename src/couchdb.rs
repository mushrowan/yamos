use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::Rng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use urlencoding::encode as urlencode;

// livesync chunks at ~32 bytes. or so i think
const CHUNK_SIZE: usize = 32;

#[derive(Clone)]
pub struct CouchDbClient {
    client: Client,
    base_url: String,
    database: String,
    auth_header: String,
}

// i tried to get "notes" working but it kept corrupting my database. i've left it in, in case
// a future version of me can figure out what is the dealio with it
/// Main document for a note - references chunks via children array
/// type "plain" = chunked text, "newnote" = chunked binary, "notes" = legacy (avoid)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteDoc {
    #[serde(rename = "_id")]
    pub id: String,
    #[serde(rename = "_rev", skip_serializing_if = "Option::is_none")]
    pub rev: Option<String>,
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub data: String, // only for legacy "notes" type
    pub ctime: u64,
    pub mtime: u64,
    pub size: u64,
    #[serde(rename = "type")]
    pub doc_type: String,
    pub children: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted: Option<bool>,
    #[serde(default)]
    pub eden: serde_json::Value,
}

/// Chunk document - contains raw string data (not base64!)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeafDoc {
    #[serde(rename = "_id")]
    pub id: String,
    #[serde(rename = "_rev", skip_serializing_if = "Option::is_none")]
    pub rev: Option<String>,
    pub data: String,
    #[serde(rename = "type")]
    pub doc_type: String,
}

#[derive(Debug, Deserialize)]
pub struct SaveResponse {
    pub ok: bool,
    pub id: String,
    pub rev: String,
}

#[derive(Debug, Deserialize)]
pub struct AllDocsRow {
    pub id: String,
    pub key: String,
    pub value: AllDocsValue,
    // can be NoteDoc or LeafDoc, so we use Value and parse later
    #[serde(default)]
    pub doc: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct AllDocsValue {
    pub rev: String,
    #[serde(default)]
    pub deleted: bool,
}

#[derive(Debug, Deserialize)]
pub struct AllDocsResponse {
    pub total_rows: u64,
    pub offset: u64,
    pub rows: Vec<AllDocsRow>,
}

impl CouchDbClient {
    pub fn new(url: &str, database: &str, username: &str, password: &str) -> Result<Self> {
        let auth = format!("{}:{}", username, password);
        let auth_header = format!("Basic {}", BASE64.encode(auth.as_bytes()));

        let base_url = url.trim_end_matches('/').to_string();

        Ok(Self {
            client: Client::new(),
            base_url,
            database: database.to_string(),
            auth_header,
        })
    }

    fn doc_url(&self, doc_id: &str) -> String {
        format!("{}/{}/{}", self.base_url, self.database, urlencode(doc_id))
    }

    /// lists notes, filtering out chunks (h:*), system docs (_*), and soft-deleted notes
    pub async fn list_notes(&self) -> Result<Vec<String>> {
        let url = format!(
            "{}/{}/_all_docs?include_docs=true",
            self.base_url, self.database
        );

        let response = self
            .client
            .get(&url)
            .header("Authorization", &self.auth_header)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Failed to list documents: {} - {}", status, body));
        }

        let all_docs: AllDocsResponse = response.json().await?;

        // filter out chunk documents (h:*), system docs (_*), tombstones, and soft-deleted
        let notes: Vec<String> = all_docs
            .rows
            .into_iter()
            .filter(|row| {
                !row.id.starts_with("h:")
                    && !row.id.starts_with("_")
                    && !row.value.deleted
                    && !row.doc.as_ref().is_some_and(|d| d.get("deleted") == Some(&serde_json::Value::Bool(true)))
            })
            .map(|row| row.id)
            .collect();

        Ok(notes)
    }

    pub async fn get_note(&self, id: &str) -> Result<NoteDoc> {
        let url = self.doc_url(id);

        let response = self
            .client
            .get(&url)
            .header("Authorization", &self.auth_header)
            .send()
            .await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(anyhow!("Note not found: {}", id));
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Failed to get note: {} - {}", status, body));
        }

        let doc: NoteDoc = response.json().await?;
        Ok(doc)
    }

    /// fetches chunks for "plain", decodes base64 for legacy "notes"
    pub async fn decode_content(&self, doc: &NoteDoc) -> Result<String> {
        if doc.doc_type == "notes" {
            // legacy format: base64 encoded data in document
            let bytes = BASE64.decode(&doc.data)?;
            let content = String::from_utf8(bytes)?;
            Ok(content)
        } else {
            // chunked format: fetch all leaf documents
            let mut content = String::new();
            for chunk_id in &doc.children {
                let chunk_content = self.get_leaf(chunk_id).await?;
                content.push_str(&chunk_content);
            }
            Ok(content)
        }
    }

    async fn get_leaf(&self, chunk_id: &str) -> Result<String> {
        let url = self.doc_url(chunk_id);

        let response = self
            .client
            .get(&url)
            .header("Authorization", &self.auth_header)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Failed to get chunk {}: {} - {}",
                chunk_id,
                status,
                body
            ));
        }

        let leaf: LeafDoc = response.json().await?;
        Ok(leaf.data)
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    // inb4 "there's a crate for this" shut up
    fn generate_chunk_id() -> String {
        const CHARSET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
        let mut rng = rand::rng();
        let id: String = (0..13)
            .map(|_| {
                let idx = rng.random_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();
        format!("h:{}", id)
    }

    fn split_into_chunks(content: &str) -> Vec<(String, String)> {
        let mut chunks = Vec::new();
        let mut current_chunk = String::new();
        let mut current_size = 0;

        // split on character boundaries to avoid corrupting multi-byte UTF-8
        for ch in content.chars() {
            let ch_len = ch.len_utf8();
            if current_size + ch_len > CHUNK_SIZE && !current_chunk.is_empty() {
                chunks.push((Self::generate_chunk_id(), current_chunk));
                current_chunk = String::new();
                current_size = 0;
            }
            current_chunk.push(ch);
            current_size += ch_len;
        }

        if !current_chunk.is_empty() || chunks.is_empty() {
            chunks.push((Self::generate_chunk_id(), current_chunk));
        }

        chunks
    }

    async fn save_leaf(&self, chunk_id: &str, data: &str) -> Result<()> {
        let leaf = LeafDoc {
            id: chunk_id.to_string(),
            rev: None,
            data: data.to_string(),
            doc_type: "leaf".to_string(),
        };

        let url = self.doc_url(chunk_id);

        let response = self
            .client
            .put(&url)
            .header("Authorization", &self.auth_header)
            .header("Content-Type", "application/json")
            .json(&leaf)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Failed to save chunk {}: {} - {}",
                chunk_id,
                status,
                body
            ));
        }

        Ok(())
    }

    async fn delete_leaf(&self, chunk_id: &str) -> Result<()> {
        let url = self.doc_url(chunk_id);

        // get current rev first
        let response = self
            .client
            .get(&url)
            .header("Authorization", &self.auth_header)
            .send()
            .await?;

        if !response.status().is_success() {
            // already gone or never existed, that's fine
            return Ok(());
        }

        let leaf: LeafDoc = response.json().await?;
        let Some(rev) = leaf.rev else {
            return Ok(());
        };

        let delete_url = format!("{}?rev={}", url, urlencode(&rev));
        let response = self
            .client
            .delete(&delete_url)
            .header("Authorization", &self.auth_header)
            .send()
            .await?;

        if !response.status().is_success() && response.status() != reqwest::StatusCode::NOT_FOUND {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            tracing::warn!("Failed to delete chunk {}: {} - {}", chunk_id, status, body);
        }

        Ok(())
    }

    /// splits content into chunks, saves them, then saves the main doc pointing to them
    pub async fn save_note(&self, id: &str, content: &str) -> Result<SaveResponse> {
        // try to get existing doc first to get the _rev
        let existing = self.get_note(id).await.ok();
        let now = Self::now_ms();

        // delete old chunks to avoid orphaning them
        if let Some(ref old_doc) = existing {
            for old_chunk_id in &old_doc.children {
                let _ = self.delete_leaf(old_chunk_id).await;
            }
        }

        // split content into chunks
        let chunks = Self::split_into_chunks(content);
        let chunk_ids: Vec<String> = chunks.iter().map(|(id, _)| id.clone()).collect();

        tracing::debug!(
            "Saving note {} with {} chunks (size={})",
            id,
            chunks.len(),
            content.len()
        );

        // save all chunk documents first
        for (chunk_id, chunk_data) in &chunks {
            self.save_leaf(chunk_id, chunk_data).await?;
            tracing::debug!("Saved chunk {} ({} bytes)", chunk_id, chunk_data.len());
        }

        // create the main document with children references
        let doc = NoteDoc {
            id: id.to_string(),
            rev: existing.as_ref().and_then(|d| d.rev.clone()),
            path: id.to_string(),
            data: String::new(), // No direct data for "plain" type
            ctime: existing.as_ref().map(|d| d.ctime).unwrap_or(now),
            mtime: now,
            size: content.len() as u64,
            doc_type: "plain".to_string(),
            children: chunk_ids,
            deleted: None,
            eden: serde_json::json!({}),
        };

        let url = self.doc_url(id);

        if let Ok(json) = serde_json::to_string_pretty(&doc) {
            tracing::debug!("Saving main document:\n{}", json);
        }

        let response = self
            .client
            .put(&url)
            .header("Authorization", &self.auth_header)
            .header("Content-Type", "application/json")
            .json(&doc)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Failed to save note: {} - {}", status, body));
        }

        let save_response: SaveResponse = response.json().await?;
        tracing::info!(
            "Successfully saved note {} with {} chunks",
            id,
            chunks.len()
        );
        Ok(save_response)
    }

    pub async fn append_to_note(&self, id: &str, content: &str) -> Result<SaveResponse> {
        let existing = self.get_note(id).await?;
        let current_content = self.decode_content(&existing).await?;
        let new_content = format!("{}\n{}", current_content, content);
        self.save_note(id, &new_content).await
    }

    /// soft-deletes a note by setting deleted: true (livesync expects this, not couchDB tombstones)
    pub async fn delete_note(&self, id: &str) -> Result<()> {
        let existing = self.get_note(id).await?;

        let doc = NoteDoc {
            id: existing.id,
            rev: existing.rev,
            path: existing.path,
            data: existing.data,
            ctime: existing.ctime,
            mtime: Self::now_ms(),
            size: existing.size,
            doc_type: existing.doc_type,
            children: existing.children,
            deleted: Some(true),
            eden: existing.eden,
        };

        let url = self.doc_url(id);

        let response = self
            .client
            .put(&url)
            .header("Authorization", &self.auth_header)
            .header("Content-Type", "application/json")
            .json(&doc)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Failed to delete note: {} - {}", status, body));
        }

        tracing::info!("Soft-deleted note {}", id);
        Ok(())
    }

    pub async fn test_connection(&self) -> Result<()> {
        let url = format!("{}/{}", self.base_url, self.database);

        let response = self
            .client
            .get(&url)
            .header("Authorization", &self.auth_header)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Failed to connect to CouchDB: {} - {}",
                status,
                body
            ));
        }

        Ok(())
    }
}
