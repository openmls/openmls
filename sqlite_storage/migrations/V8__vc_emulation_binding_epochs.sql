-- Projection of the emulation bindings onto the derivation epochs they bind.
-- One row per (higher-level group, derivation epoch) pair, rewritten whole
-- whenever the group's binding record is written. The binding record itself is
-- an opaque blob, so this table is what lets the guarded delete of a
-- derivation epoch's state find the groups still bound to it and keep the
-- state alive for them.
CREATE TABLE vc_emulation_binding_epochs (
    provider_version INTEGER NOT NULL,
    group_id BLOB NOT NULL,
    epoch_id BLOB NOT NULL,
    PRIMARY KEY (group_id, epoch_id)
);

-- The guarded delete queries by epoch alone, which the group-first primary key
-- cannot serve.
CREATE INDEX vc_emulation_binding_epochs_epoch_id
    ON vc_emulation_binding_epochs (epoch_id);
