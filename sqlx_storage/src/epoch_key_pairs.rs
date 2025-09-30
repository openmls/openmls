// SPDX-FileCopyrightText: 2023 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::marker::PhantomData;

use openmls_traits::storage::{CURRENT_VERSION, Entity};

pub(crate) struct StorableEpochKeyPairs<EpochKeyPairs: Entity<CURRENT_VERSION>>(
    PhantomData<EpochKeyPairs>,
);

pub(super) struct StorableEpochKeyPairsRef<'a, EpochKeyPairs: Entity<CURRENT_VERSION>>(
    pub &'a [EpochKeyPairs],
);
