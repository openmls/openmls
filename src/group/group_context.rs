use super::*;

impl GroupContext {
    /// Create a new group context
    pub fn new(
        group_id: GroupId,
        epoch: GroupEpoch,
        tree_hash: Vec<u8>,
        confirmed_transcript_hash: Vec<u8>,
        extensions: Vec<Box<dyn Extension>>,
    ) -> Result<Self, CodecError> {
        let mut group_context = GroupContext {
            group_id,
            epoch,
            tree_hash,
            confirmed_transcript_hash,
            extensions,
            serialized: vec![],
        };
        let serialized = group_context.encode_detached()?;
        group_context.serialized = serialized.to_vec();
        Ok(group_context)
    }

    /// Create the group context of a new epoch from the one of the previous
    /// epoch.
    pub(crate) fn from_previous_group_context(
        group_context: &GroupContext,
        tree_hash: Vec<u8>,
        confirmed_transcript_hash: Vec<u8>,
    ) -> Result<Self, CodecError> {
        let mut epoch = group_context.epoch();
        epoch.increment();
        GroupContext::new(
            group_context.group_id.clone(),
            epoch,
            tree_hash,
            confirmed_transcript_hash,
            group_context.extensions.clone(),
        )
    }

    /// Create the `GroupContext` needed upon creation of a new group.
    pub fn create_initial_group_context(
        ciphersuite: &Ciphersuite,
        group_id: GroupId,
        tree_hash: Vec<u8>,
        extensions: Vec<Box<dyn Extension>>,
    ) -> Result<Self, CodecError> {
        Self::new(
            group_id,
            GroupEpoch(0),
            tree_hash,
            zero(ciphersuite.hash_length()),
            extensions,
        )
    }

    /// Return the serialized group context
    pub fn serialized(&self) -> &[u8] {
        &self.serialized
    }

    /// Return the group ID
    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    /// Return the epoch
    pub fn epoch(&self) -> GroupEpoch {
        self.epoch
    }

    /// Return the extensions
    pub fn extensions(&self) -> &[Box<dyn Extension>] {
        &self.extensions
    }
}
