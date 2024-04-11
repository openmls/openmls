#[derive(Debug, Clone, Default)]
pub struct OpenMlsTypes;

use openmls_traits::storage::*;

use crate::ciphersuite::hash_ref::ProposalRef;
use crate::group::GroupId;
use crate::group::QueuedProposal;
use crate::treesync::TreeSync;

impl Entity<1> for QueuedProposal {}
impl QueuedProposalEntity<1> for QueuedProposal {}

impl Entity<1> for TreeSync {}
impl TreeSyncEntity<1> for TreeSync {}

impl Key<1> for GroupId {}
impl GroupIdKey<1> for GroupId {}

impl Key<1> for ProposalRef {}
impl Entity<1> for ProposalRef {}
impl ProposalRefKey<1> for ProposalRef {}
impl ProposalRefEntity<1> for ProposalRef {}

impl Types<1> for OpenMlsTypes {
    type QueuedProposal = QueuedProposal;
    type GroupId = GroupId;
    type ProposalRef = ProposalRef;
    type TreeSync = crate::treesync::TreeSync;
}
