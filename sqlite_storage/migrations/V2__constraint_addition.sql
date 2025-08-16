-- Create new table that allows for application export tree data
CREATE TABLE openmls_group_data_new (
    provider_version INTEGER NOT NULL,
    group_id BLOB NOT NULL,
    data_type TEXT NOT NULL CHECK (data_type IN (
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
    )),
    group_data BLOB NOT NULL,
    PRIMARY KEY (group_id, data_type)
);

-- Copy existing data to the new table
INSERT INTO openmls_group_data_new (provider_version, group_id, data_type, group_data)
SELECT provider_version, group_id, data_type, group_data
FROM openmls_group_data;

-- Drop the old table
DROP TABLE openmls_group_data;

-- Rename the new table to the original name
ALTER TABLE openmls_group_data_new RENAME TO openmls_group_data;