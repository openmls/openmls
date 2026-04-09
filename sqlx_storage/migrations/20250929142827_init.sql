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
            'group_epoch_secrets'
        )
    ),
    group_data BLOB NOT NULL,
    PRIMARY KEY (group_id, data_type)
);

CREATE TABLE openmls_proposal (
    group_id BLOB NOT NULL,
    proposal_ref BLOB NOT NULL,
    proposal BLOB NOT NULL,
    PRIMARY KEY (group_id, proposal_ref)
);

CREATE TABLE openmls_own_leaf_node (
    group_id BLOB PRIMARY KEY,
    leaf_node BLOB NOT NULL
);

CREATE TABLE openmls_signature_key (
    public_key BLOB PRIMARY KEY,
    signature_key BLOB NOT NULL
);

CREATE TABLE openmls_encryption_key (
    public_key BLOB PRIMARY KEY,
    key_pair BLOB NOT NULL
);

CREATE TABLE openmls_epoch_key_pairs (
    group_id BLOB NOT NULL,
    epoch_id BLOB NOT NULL,
    leaf_index INTEGER NOT NULL,
    key_pairs BLOB NOT NULL,
    PRIMARY KEY (group_id, epoch_id, leaf_index)
);

CREATE TABLE openmls_key_package (
    key_package_ref BLOB PRIMARY KEY,
    key_package BLOB NOT NULL
);

CREATE TABLE openmls_psk (psk_id BLOB PRIMARY KEY, psk_bundle BLOB NOT NULL);
