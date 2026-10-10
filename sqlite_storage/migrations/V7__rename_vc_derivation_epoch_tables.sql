-- Rename the virtual-client tables to the derivation-epoch vocabulary. The
-- secrets table is rebuilt because its CHECK constraint names the secret
-- types and sqlite cannot alter a CHECK constraint in place.
CREATE TABLE vc_derivation_epoch_secrets (
    provider_version INTEGER NOT NULL,
    epoch_id BLOB NOT NULL,
    secret_type TEXT NOT NULL CHECK (secret_type IN (
        'pprf',
        'derivation_epoch_state'
    )),
    vc_secret BLOB NOT NULL,
    PRIMARY KEY (epoch_id, secret_type)
);

INSERT INTO vc_derivation_epoch_secrets (provider_version, epoch_id, secret_type, vc_secret)
SELECT
    provider_version,
    epoch_id,
    CASE secret_type
        WHEN 'emulation_epoch_state' THEN 'derivation_epoch_state'
        ELSE secret_type
    END,
    vc_secret
FROM vc_emulation_group_secrets;

DROP TABLE vc_emulation_group_secrets;

ALTER TABLE registered_vc_emulation_epochs RENAME TO registered_vc_derivation_epochs;
