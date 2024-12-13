CREATE TABLE IF NOT EXISTS openmls_encryption_keys (
    provider_version INTEGER NOT NULL,
    public_key BLOB PRIMARY KEY,
    key_pair BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS openmls_epoch_keys_pairs (
    provider_version INTEGER NOT NULL,
    group_id BLOB NOT NULL,
    epoch_id BLOB NOT NULL,
    leaf_index INTEGER NOT NULL,
    key_pairs BLOB NOT NULL,
    PRIMARY KEY (group_id, epoch_id, leaf_index)
);      

CREATE TABLE IF NOT EXISTS openmls_group_data (
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
        'group_epoch_secrets'
    )),
    group_data BLOB NOT NULL,
    PRIMARY KEY (group_id, data_type)
);
        
CREATE TABLE IF NOT EXISTS openmls_key_packages (
    provider_version INTEGER NOT NULL,
    key_package_ref BLOB PRIMARY KEY,
    key_package BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS openmls_own_leaf_nodes (
    provider_version INTEGER NOT NULL,
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id BLOB NOT NULL,
    leaf_node BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS openmls_proposals (
    provider_version INTEGER NOT NULL,
    group_id BLOB NOT NULL,
    proposal_ref BLOB NOT NULL,
    proposal BLOB NOT NULL,
    PRIMARY KEY (group_id, proposal_ref)
);

CREATE TABLE IF NOT EXISTS openmls_psks (
    provider_version INTEGER NOT NULL,
    psk_id BLOB PRIMARY KEY,
    psk_bundle BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS openmls_signature_keys (
    provider_version INTEGER NOT NULL,
    public_key BLOB PRIMARY KEY,
    signature_key BLOB NOT NULL
);
