-- Create new table for virtual clients key material
CREATE TABLE vc_emulation_group_secrets (
    provider_version INTEGER NOT NULL,
    epoch_id BLOB NOT NULL,
    secret_type TEXT NOT NULL CHECK (secret_type IN (
        'epoch_base_secret',
        'epoch_encryption_key'
    )),
    vc_secret BLOB NOT NULL,
    PRIMARY KEY (epoch_id, secret_type)
);
