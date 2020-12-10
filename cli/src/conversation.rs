/// A conversation is a list of messages (strings).
#[derive(Default, Debug)]
pub struct Conversation {
    messages: Vec<String>,
}

impl Conversation {
    /// Add a message string to the conversation list.
    pub fn add(&mut self, msg: String) {
        self.messages.push(msg)
    }

    /// Get a list of messages in the conversation.
    /// The function returns the `last_n` messages.
    #[allow(dead_code)]
    pub fn get(&self, last_n: usize) -> Option<&[String]> {
        let num_messages = self.messages.len();
        let start = if last_n > num_messages {
            0
        } else {
            num_messages - last_n
        };
        self.messages.get(start..num_messages)
    }
}
