use super::*;

impl GroupContext {
    /// Create a new group context
    pub fn new(
        group_id: GroupId,
        epoch: GroupEpoch,
        tree_hash: Vec<u8>,
        confirmed_transcript_hash: Vec<u8>,
        extensions: &[Extension],
    ) -> Result<Self, tls_codec::Error> {
        let group_context = GroupContext {
            group_id,
            epoch,
            tree_hash: tree_hash.into(),
            confirmed_transcript_hash: confirmed_transcript_hash.into(),
            extensions: extensions.into(),
        };
        Ok(group_context)
    }
    /// Create the `GroupContext` needed upon creation of a new group.
    pub fn create_initial_group_context(
        ciphersuite: &Ciphersuite,
        group_id: GroupId,
        tree_hash: Vec<u8>,
        extensions: &[Extension],
    ) -> Result<Self, tls_codec::Error> {
        Self::new(
            group_id,
            GroupEpoch(0),
            tree_hash,
            zero(ciphersuite.hash_length()),
            extensions,
        )
    }

    /// Return the group ID
    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }
    /// Return the epoch
    pub fn epoch(&self) -> GroupEpoch {
        self.epoch
    }
    /// Return the extensions of the context
    pub fn extensions(&self) -> &[Extension] {
        self.extensions.as_slice()
    }
    /// Get the required capabilities extension.
    pub fn required_capabilities(&self) -> Option<&RequiredCapabilitiesExtension> {
        self.extensions
            .iter()
            .find(|e| e.extension_type() == ExtensionType::RequiredCapabilities)
            .map(|e| e.as_required_capabilities_extension().ok())
            .flatten()
    }
}
