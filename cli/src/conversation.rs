use serde::{Deserialize, Serialize};

/// A conversation is a list of messages (strings).
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Conversation {
    messages: Vec<ConversationMessage>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct ConversationMessage {
    pub author: String,
    pub message: String,
}

impl Conversation {
    /// Add a message string to the conversation list.
    pub fn add(&mut self, conversation_message: ConversationMessage) {
        self.messages.push(conversation_message)
    }

    /// Get a list of messages in the conversation.
    /// The function returns the `last_n` messages.
    #[allow(dead_code)]
    pub fn get(&self, last_n: usize) -> Option<&[ConversationMessage]> {
        let num_messages = self.messages.len();
        let start = if last_n > num_messages {
            0
        } else {
            num_messages - last_n
        };
        self.messages.get(start..num_messages)
    }
}

impl ConversationMessage {
    pub fn new(message: String, author: String) -> Self {
        Self { author, message }
    }
}
