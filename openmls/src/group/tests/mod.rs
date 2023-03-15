//! Unit tests for the core group

#[cfg(test)]
mod external_add_proposal;
#[cfg(test)]
mod external_remove_proposal;
#[cfg(test)]
pub mod kat_messages;
#[cfg(test)]
pub mod kat_transcript_hashes;
#[cfg(test)]
mod test_commit_validation;
#[cfg(test)]
mod test_encoding;
#[cfg(test)]
mod test_external_commit_validation;
#[cfg(test)]
mod test_framing;
#[cfg(test)]
mod test_framing_validation;
#[cfg(test)]
mod test_group;
#[cfg(test)]
mod test_past_secrets;
#[cfg(test)]
mod test_proposal_validation;
#[cfg(test)]
mod test_remove_operation;
#[cfg(test)]
mod test_wire_format_policy;
#[cfg(test)]
pub(crate) mod utils;

pub(crate) mod tree_printing;
