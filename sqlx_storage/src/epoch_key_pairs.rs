use std::marker::PhantomData;

use openmls_traits::storage::{CURRENT_VERSION, Entity};

pub(crate) struct StorableEpochKeyPairs<EpochKeyPairs: Entity<CURRENT_VERSION>>(
    PhantomData<EpochKeyPairs>,
);

pub(super) struct StorableEpochKeyPairsRef<'a, EpochKeyPairs: Entity<CURRENT_VERSION>>(
    pub &'a [EpochKeyPairs],
);
