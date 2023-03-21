use openmls_traits::{signatures::Signer, OpenMlsCryptoProvider};

use super::{errors::ProposeAddMemberError, MlsGroup};
use crate::{framing::MlsMessageOut, group::QueuedProposal, schedule::PreSharedKeyId};

impl MlsGroup {
    /// Creates proposals to add an external PSK to the key schedule.
    ///
    /// Returns an error if there is a pending commit.
    pub fn propose_external_psk(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        signer: &impl Signer,
        psk_id: PreSharedKeyId,
    ) -> Result<MlsMessageOut, ProposeAddMemberError> {
        self.is_operational()?;

        let add_proposal = self.group.create_presharedkey_proposal(
            self.framing_parameters(),
            psk_id.into(),
            signer,
        )?;

        self.proposal_store
            .add(QueuedProposal::from_authenticated_content(
                self.ciphersuite(),
                backend,
                add_proposal.clone(),
            )?);

        let mls_message = self.content_to_mls_message(add_proposal, backend)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok(mls_message)
    }
}
