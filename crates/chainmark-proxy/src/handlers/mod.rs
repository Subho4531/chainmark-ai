pub mod openai;
pub mod anthropic;
pub mod mcp;
pub mod cloak;
pub mod evidence;

pub use openai::handle_chat_completions;
pub use anthropic::handle_messages;
pub use mcp::{handle_mcp_message, handle_mcp_sse};
pub use cloak::{handle_cloak, handle_uncloak_path, handle_uncloak_body};
pub use evidence::{handle_health, handle_export_evidence, handle_verify_evidence, handle_list_sessions};
