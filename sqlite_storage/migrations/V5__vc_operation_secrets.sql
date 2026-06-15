-- Per-emulation-epoch Virtual Client Operation Secret Tree. One row per
-- emulation epoch, holding the serialized tree (node secrets plus per-leaf
-- operation ratchets). Written back after every ratchet advance, stored
-- separately from the static emulation epoch state so per-operation writes
-- do not rewrite the static fields.
CREATE TABLE vc_operation_trees (
    provider_version INTEGER NOT NULL,
    epoch_id BLOB NOT NULL,
    operation_tree BLOB NOT NULL,
    PRIMARY KEY (epoch_id)
);
