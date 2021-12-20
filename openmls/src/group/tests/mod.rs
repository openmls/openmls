//! Unit tests for the core group

pub mod kat_messages;

#[cfg(any(feature = "test-utils", test))]
pub mod kat_transcripts;

#[cfg(test)]
mod test_past_secrets;
#[cfg(test)]
mod test_validation;
