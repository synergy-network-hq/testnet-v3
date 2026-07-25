use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use super::runtime::AIVMExecutionContext;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatSession {
    pub session_id: String,
    pub messages: Vec<ChatMessage>,
    pub context: HashMap<String, String>,
    pub created_at: u64,
    pub last_activity: u64,
}

#[derive(Debug)]
pub struct ChatInterface {
    sessions: HashMap<String, ChatSession>,
    model_endpoint: String,
    api_key: Option<String>,
}

impl ChatInterface {
    pub fn new() -> Self {
        ChatInterface {
            sessions: HashMap::new(),
            model_endpoint: "http://localhost:8000".to_string(), // Default GPT-OSS endpoint
            api_key: None,
        }
    }

    pub fn with_endpoint(endpoint: String) -> Self {
        ChatInterface {
            sessions: HashMap::new(),
            model_endpoint: endpoint,
            api_key: None,
        }
    }

    pub fn with_api_key(mut self, api_key: String) -> Self {
        self.api_key = Some(api_key);
        self
    }

    pub async fn chat_with_ai(
        &self,
        message: &str,
        context: &AIVMExecutionContext,
    ) -> Result<String, String> {
        let session_id = format!("session_{}", context.transaction_hash);

        // Get or create session
        let mut session = self.get_or_create_session(&session_id, context);

        // Add user message
        let user_message = ChatMessage {
            role: "user".to_string(),
            content: message.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        session.messages.push(user_message);
        session.last_activity = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Add context information
        session.context.insert(
            "transaction_hash".to_string(),
            context.transaction_hash.clone(),
        );
        session.context.insert(
            "block_height".to_string(),
            context.block_height.to_string(),
        );
        session.context.insert(
            "sender".to_string(),
            context.sender.clone(),
        );

        // Prepare request for GPT-OSS model
        let request_payload = self.prepare_chat_request(&session)?;

        // Make HTTP request to GPT-OSS endpoint
        let response = self.make_chat_request(&request_payload).await?;

        // Parse response
        let ai_response = self.parse_chat_response(&response)?;

        // Add AI response to session
        let ai_message = ChatMessage {
            role: "assistant".to_string(),
            content: ai_response.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        session.messages.push(ai_message);

        // Update session
        self.sessions.insert(session_id, session);

        Ok(ai_response)
    }

    fn get_or_create_session(
        &self,
        session_id: &str,
        context: &AIVMExecutionContext,
    ) -> ChatSession {
        if let Some(session) = self.sessions.get(session_id) {
            session.clone()
        } else {
            ChatSession {
                session_id: session_id.to_string(),
                messages: Vec::new(),
                context: HashMap::new(),
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                last_activity: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            }
        }
    }

    fn prepare_chat_request(&self, session: &ChatSession) -> Result<Value, String> {
        // Format messages for GPT-OSS API
        let messages: Vec<Value> = session
            .messages
            .iter()
            .map(|msg| {
                json!({
                    "role": msg.role,
                    "content": msg.content
                })
            })
            .collect();

        let mut request = json!({
            "model": "openai/gpt-oss-20b",
            "messages": messages,
            "max_tokens": 1000,
            "temperature": 0.7,
            "top_p": 0.9,
            "frequency_penalty": 0.0,
            "presence_penalty": 0.0,
            "stream": false
        });

        // Add system message to make AI more personable
        let system_message = json!({
            "role": "system",
            "content": "You are a helpful AI assistant working within the Synergy Network blockchain system. You help users understand smart contract executions, provide insights about transactions, and assist with blockchain operations. Be friendly, informative, and professional. Always explain technical concepts clearly."
        });

        if let Some(messages_array) = request.get_mut("messages") {
            if let Some(array) = messages_array.as_array_mut() {
                array.insert(0, system_message);
            }
        }

        Ok(request)
    }

    async fn make_chat_request(&self, payload: &Value) -> Result<String, String> {
        let client = reqwest::Client::new();

        let mut request = client
            .post(&self.model_endpoint)
            .header("Content-Type", "application/json");

        if let Some(api_key) = &self.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        let response = request
            .json(payload)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        if response.status().is_success() {
            let text = response
                .text()
                .await
                .map_err(|e| format!("Failed to read response: {}", e))?;
            Ok(text)
        } else {
            Err(format!("API request failed with status: {}", response.status()))
        }
    }

    fn parse_chat_response(&self, response_text: &str) -> Result<String, String> {
        let response: Value = serde_json::from_str(response_text)
            .map_err(|e| format!("Failed to parse response JSON: {}", e))?;

        if let Some(choices) = response.get("choices") {
            if let Some(choices_array) = choices.as_array() {
                if let Some(first_choice) = choices_array.get(0) {
                    if let Some(message) = first_choice.get("message") {
                        if let Some(content) = message.get("content") {
                            if let Some(content_str) = content.as_str() {
                                return Ok(content_str.to_string());
                            }
                        }
                    }
                }
            }
        }

        Err("Unexpected response format from AI model".to_string())
    }

    pub fn get_session(&self, session_id: &str) -> Option<&ChatSession> {
        self.sessions.get(session_id)
    }

    pub fn get_all_sessions(&self) -> Vec<&ChatSession> {
        self.sessions.values().collect()
    }

    pub fn clear_session(&mut self, session_id: &str) {
        self.sessions.remove(session_id);
    }

    pub fn clear_all_sessions(&mut self) {
        self.sessions.clear();
    }

    pub fn get_session_stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("total_sessions".to_string(), self.sessions.len());
        stats.insert(
            "total_messages".to_string(),
            self.sessions.values().map(|s| s.messages.len()).sum(),
        );
        stats
    }
}
