-- The emulation epoch an emulation group registered for its current group
-- epoch. One row per emulation group, holding the serialized registration
-- record (group epoch plus derived emulation epoch id). Written by
-- register_vc_emulation_epoch so a repeated call in the same group epoch
-- returns the existing epoch id instead of consuming the forward-secure
-- exporter again.
CREATE TABLE registered_vc_emulation_epochs (
    provider_version INTEGER NOT NULL,
    group_id BLOB NOT NULL,
    registration BLOB NOT NULL,
    PRIMARY KEY (group_id)
);
