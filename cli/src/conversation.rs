use std::collections::HashMap;

#[derive(Default, Debug)]
pub struct Conversation {
    messages: Vec<String>,
}

impl Conversation {
    pub fn add(&mut self, msg: String) {
        self.messages.push(msg)
    }
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
