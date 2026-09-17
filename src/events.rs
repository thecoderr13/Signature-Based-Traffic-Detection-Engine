//! Every step the pipeline takes — reading a file, calling an API, matching
//! a flow — is emitted as a `PipelineEvent` on a broadcast channel. The web
//! UI subscribes to `/api/events` (Server-Sent Events) and renders these
//! live, which is what makes the tool's internals visible to a third party
//! instead of a black box.

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Stage {
    System,
    Ingestion,
    Signatures,
    Detection,
    Report,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Level {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct PipelineEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub stage: Stage,
    pub level: Level,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

impl PipelineEvent {
    pub fn new(stage: Stage, level: Level, message: impl Into<String>) -> Self {
        PipelineEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            stage,
            level,
            message: message.into(),
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: serde_json::Value) -> Self {
        self.detail = Some(detail);
        self
    }
}
