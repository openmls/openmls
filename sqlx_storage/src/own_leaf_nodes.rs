use openmls_traits::storage::{CURRENT_VERSION, Entity};

pub(crate) struct StorableLeafNode<LeafNode: Entity<CURRENT_VERSION>>(pub LeafNode);

pub(crate) struct StorableLeafNodeRef<'a, LeafNode: Entity<CURRENT_VERSION>>(pub &'a LeafNode);
