//! Unit tests for the core group

mod aad;
#[cfg(feature = "extensions-draft-08")]
mod app_data_update_proposal_validation;

mod capabilities_check;
mod commit_validation;
mod encoding;
mod external_add_proposal;
mod external_commit;
mod external_commit_builder;
mod external_commit_validation;
mod external_group_context_extensions_proposal;
mod external_join_add_proposal;
mod external_remove_proposal;
mod framing;
mod framing_validation;
mod group;
mod group_context_extensions;
mod key_package_in;
mod past_secrets;
mod proposal_validation;
mod remove_operation;
mod wire_format_policy;
