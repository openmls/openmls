use openmls_traits::storage::{CURRENT_VERSION, Entity, Key};

pub(crate) struct StorablePskBundle<PskBundle: Entity<CURRENT_VERSION>>(PskBundle);

pub(super) struct StorablePskBundleRef<'a, PskBundle: Entity<CURRENT_VERSION>>(pub &'a PskBundle);

pub(super) struct StorablePskIdRef<'a, PskId: Key<CURRENT_VERSION>>(pub &'a PskId);
