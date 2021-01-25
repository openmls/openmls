use std::str;

use openmls::prelude::*;

// Callbacks
fn member_added(
    managed_group: &ManagedGroup,
    _aad: &[u8],
    sender: &Credential,
    added_member: &Credential,
) {
    println!(
        "AddProposal received in group '{}' by '{}': '{}' added '{}'",
        str::from_utf8(&managed_group.group_id().as_slice()).unwrap(),
        str::from_utf8(&managed_group.credential().identity()).unwrap(),
        str::from_utf8(sender.identity()).unwrap(),
        str::from_utf8(added_member.identity()).unwrap(),
    );
}
fn invalid_message_received(managed_group: &ManagedGroup, error: InvalidMessageError) {
    match error {
        InvalidMessageError::InvalidCiphertext(aad) => {
            println!(
                "Invalid ciphertext message received in group '{}' by '{}' with AAD {:?}",
                str::from_utf8(&managed_group.group_id().as_slice()).unwrap(),
                str::from_utf8(&managed_group.credential().identity()).unwrap(),
                aad
            );
        }
        InvalidMessageError::CommitError(e) => {
            println!("An error occured when applying a Commit message: {:?}", e);
        }
        InvalidMessageError::CommitWithInvalidProposals(e) => {
            println!(
                "A Commit message with one ore more invalid proposals was received: {:?}",
                e
            );
        }
        InvalidMessageError::MembershipTagMismatch => {
            println!("The membership tag did not match");
        }
        InvalidMessageError::GroupError(e) => {
            println!("An error in the managed group occurred: {:?}", e);
        }
    }
}
fn error_occurred(managed_group: &ManagedGroup, error: ManagedGroupError) {
    println!(
        "Error occured in group {}: {:?}",
        str::from_utf8(&managed_group.group_id().as_slice()).unwrap(),
        error
    );
}

pub fn default_callbacks() -> ManagedGroupCallbacks {
    ManagedGroupCallbacks::new()
        .with_member_added(member_added)
        .with_invalid_message_received(invalid_message_received)
        .with_error_occured(error_occurred)
}
