-- Binding between higher-level groups and emulation epochs for the
-- virtual-clients reuse-guard derivation. Each higher-level group has at
-- most one binding, recording the emulation epoch whose currently-active
-- virtual-client LeafNode produced the group's current key material.
-- Updated when a VC commit is merged on the higher-level group.
CREATE TABLE vc_emulation_bindings (
    provider_version INTEGER NOT NULL,
    group_id BLOB NOT NULL,
    epoch_id BLOB NOT NULL,
    PRIMARY KEY (group_id)
);
