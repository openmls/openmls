-- Bindings between higher-level groups and emulation epochs for the
-- virtual-clients reuse-guard derivation. One row per higher-level group,
-- holding the serialized per-epoch binding record: for each recent epoch of
-- the group, the emulation epoch whose virtual-client LeafNode was active at
-- that epoch. Updated on every commit merged on the higher-level group.
CREATE TABLE vc_emulation_bindings (
    provider_version INTEGER NOT NULL,
    group_id BLOB NOT NULL,
    bindings BLOB NOT NULL,
    PRIMARY KEY (group_id)
);
