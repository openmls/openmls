use std::error::Error;

#[repr(u16)]
#[derive(Debug)]
pub enum KeyScheduleError {
    SecretReuseError = 0,
}

implement_enum_display!(KeyScheduleError);

impl Error for KeyScheduleError {
    fn description(&self) -> &str {
        match self {
            KeyScheduleError::SecretReuseError => {
                "The Secret was already used and deleted to achieve forward secrecy."
            }
        }
    }
}
