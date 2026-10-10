-- Store emulation bindings and the derivation epoch log as one row per entry
-- instead of one opaque record per group.
DROP TABLE vc_emulation_bindings;
DROP TABLE registered_vc_derivation_epochs;

CREATE TABLE vc_emulation_bindings (
    provider_version INTEGER NOT NULL,
    group_id BLOB NOT NULL,
    group_epoch BLOB NOT NULL,
    epoch_id BLOB NOT NULL,
    binding BLOB NOT NULL,
    PRIMARY KEY (group_id, group_epoch)
);

CREATE TABLE vc_derivation_epoch_log_entries (
    provider_version INTEGER NOT NULL,
    group_id BLOB NOT NULL,
    epoch_id BLOB NOT NULL,
    entry BLOB NOT NULL,
    PRIMARY KEY (group_id, epoch_id)
);

-- The sweep queries by epoch alone, which the group-first primary keys cannot
-- serve.
CREATE INDEX vc_emulation_bindings_epoch_id
    ON vc_emulation_bindings (epoch_id);
CREATE INDEX vc_derivation_epoch_log_entries_epoch_id
    ON vc_derivation_epoch_log_entries (epoch_id);
