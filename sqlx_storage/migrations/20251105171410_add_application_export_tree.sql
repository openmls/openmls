-- Migration: Add application_export_tree to openmls_group_data
-- 1. Rename the existing table
ALTER TABLE openmls_group_data RENAME TO openmls_group_data_old;

-- 2. Create the new table with the updated CHECK constraint
CREATE TABLE openmls_group_data (
    group_id BLOB NOT NULL,
    data_type TEXT NOT NULL CHECK (
        data_type IN (
            'join_group_config',
            'tree',
            'interim_transcript_hash',
            'context',
            'confirmation_tag',
            'group_state',
            'message_secrets',
            'resumption_psk_store',
            'own_leaf_index',
            'use_ratchet_tree_extension',
            'group_epoch_secrets',
            'application_export_tree'
        )
    ),
    group_data BLOB NOT NULL,
    PRIMARY KEY (group_id, data_type)
);

-- 3. Copy the data from the old table
INSERT INTO openmls_group_data (group_id, data_type, group_data)
SELECT group_id, data_type, group_data FROM openmls_group_data_old;

-- 4. Drop the old table
DROP TABLE openmls_group_data_old;
