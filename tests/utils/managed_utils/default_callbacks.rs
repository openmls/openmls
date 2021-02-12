use openmls::prelude::*;

fn own_identity(managed_group: &ManagedGroup) -> Vec<u8> {
    match managed_group.credential() {
        Ok(credential) => credential.identity().clone(),
        Err(_) => "us".as_bytes().to_vec(),
    }
}

// Callbacks
fn member_added(
    managed_group: &ManagedGroup,
    _aad: &[u8],
    sender: &Credential,
    added_member: &Credential,
) {
    println!(
        "AddProposal received in group '{:?}' by '{:?}': '{:?}' added '{:?}'",
        &managed_group.group_id().as_slice(),
        own_identity(managed_group),
        sender.identity(),
        added_member.identity(),
    );
}
fn invalid_message_received(managed_group: &ManagedGroup, error: InvalidMessageError) {
    match error {
        InvalidMessageError::InvalidCiphertext(aad) => {
            println!(
                "Invalid ciphertext message received in group '{:?}' by '{:?}' with AAD {:?}",
                &managed_group.group_id().as_slice(),
                own_identity(managed_group),
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
        "Error occurred in group {:?}: {:?}",
        &managed_group.group_id().as_slice(),
        error
    );
}

pub fn default_callbacks() -> ManagedGroupCallbacks {
    ManagedGroupCallbacks::new()
        .with_member_added(member_added)
        .with_invalid_message_received(invalid_message_received)
        .with_error_occurred(error_occurred)
}
