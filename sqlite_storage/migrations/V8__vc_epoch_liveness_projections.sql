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

-- Projection of the registration record onto the derivation epoch it names,
-- for the same guarded delete: an emulation group's current epoch must stay
-- alive even before any higher-level group binds it. The registration record
-- is an opaque blob, so the epoch id is kept in a column written alongside it.
-- Rows written before this migration hold NULL and are not represented until
-- the group registers again.
ALTER TABLE registered_vc_derivation_epochs
    ADD COLUMN epoch_id BLOB;

CREATE INDEX registered_vc_derivation_epochs_epoch_id
    ON registered_vc_derivation_epochs (epoch_id);
