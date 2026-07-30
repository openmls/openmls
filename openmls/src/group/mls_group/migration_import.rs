use super::*;

/// A group and all of the group-associated data it owns, deserialized from a
/// previous OpenMLS version for migration. The mirror of the older version's
/// `MlsGroup::export_for_migration`.
#[cfg_attr(
    all(feature = "test-utils", feature = "migration-import"),
    derive(serde::Serialize)
)]
#[derive(serde::Deserialize)]
pub struct GroupMigrationBundle {
    group: MlsGroup,
    epoch_encryption_key_pairs: Vec<EncryptionKeyPair>,
    update_encryption_key_pairs: Vec<EncryptionKeyPair>,
}

impl MlsGroup {
    /// Store a group as part of a storage migration.
    ///
    /// This replaces the group's persisted state for its [`GroupId`]: the
    /// single-value tables are overwritten, and the accumulate-style tables (the
    /// own leaf nodes and the proposal queue) are cleared before being rewritten.
    ///
    /// **NOTE**: This helper only addresses entries under the current key encoding. When the key
    /// encoding differs between versions (e.g. postcard → JSON), old-format entries
    /// live under different keys and are not changed; remove those with the
    /// older version's `MlsGroup::delete`.
    pub(crate) fn store_for_migration<Storage: crate::storage::StorageProvider>(
        &self,
        storage: &Storage,
    ) -> Result<(), Storage::Error> {
        self.public_group.store_for_migration(storage)?;
        storage.write_group_epoch_secrets(self.group_id(), &self.group_epoch_secrets)?;
        storage.write_own_leaf_index(self.group_id(), &self.own_leaf_index)?;
        storage.write_message_secrets(self.group_id(), &self.message_secrets_store)?;
        storage.write_resumption_psk_store(self.group_id(), &self.resumption_psk_store)?;
        storage.write_mls_join_config(self.group_id(), &self.mls_group_config)?;

        // clear `own_leaf_nodes`, and rewrite one-by-one
        storage.delete_own_leaf_nodes(self.group_id())?;
        for leaf_node in self.own_leaf_nodes.iter() {
            storage.append_own_leaf_node(self.group_id(), leaf_node)?;
        }

        storage.write_group_state(self.group_id(), &self.group_state)?;
        #[cfg(feature = "extensions-draft")]
        match &self.application_export_tree {
            Some(application_export_tree) => {
                storage.write_application_export_tree(self.group_id(), application_export_tree)?;
            }
            // No tree to write (migrating in from a version/config without
            // `extensions-draft`, or a migration whose source has none). Delete
            // any stale entry so the group's persisted state is fully replaced
            // rather than left pointing at a previously stored tree.
            None => {
                storage
                    .delete_application_export_tree::<_, ApplicationExportTree>(self.group_id())?;
            }
        }

        Ok(())
    }
}

impl GroupMigrationBundle {
    /// Store the migrated group and all of its group-associated data in the
    /// current storage format.
    ///
    /// **NOTE**: This replaces any existing state for the group's [`GroupId`], under the same [`GroupId`] encoding.
    ///
    /// Single-value tables are overwritten and the accumulate-style data
    /// (own leaf nodes, proposal queue) are cleared before writing.
    ///
    /// Old-format entries under a different key encoding are not changed.
    pub fn store<Storage: crate::storage::StorageProvider>(
        &self,
        storage: &Storage,
    ) -> Result<(), Storage::Error> {
        // Group state (config, tree, context, proposals, secrets, ...).
        self.group.store_for_migration(storage)?;

        // The group's own encryption key pairs for the current epoch.
        storage.write_encryption_epoch_key_pairs(
            self.group.group_id(),
            &self.group.epoch(),
            self.group.own_leaf_index().u32(),
            &self.epoch_encryption_key_pairs,
        )?;

        // Encryption key pairs for pending (uncommitted) update leaf nodes.
        for key_pair in &self.update_encryption_key_pairs {
            key_pair.write(storage)?;
        }

        Ok(())
    }
}
