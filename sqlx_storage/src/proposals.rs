// SPDX-FileCopyrightText: 2023 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls_traits::storage::{CURRENT_VERSION, Entity};

pub(crate) struct StorableProposal<
    Proposal: Entity<CURRENT_VERSION>,
    ProposalRef: Entity<CURRENT_VERSION>,
>(pub ProposalRef, pub Proposal);

pub(super) struct StorableProposalRef<
    'a,
    Proposal: Entity<CURRENT_VERSION>,
    ProposalRef: Entity<CURRENT_VERSION>,
>(pub &'a ProposalRef, pub &'a Proposal);
