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

-- Per-KeyPackage material a sibling retains when it processes a
-- KeyPackageUpload. One row per KeyPackage reference, holding the emulation
-- epoch the KeyPackage belongs to and the per-KeyPackage seed secret needed to
-- rederive its keys. Deleted together with the KeyPackage it describes. The
-- epoch_id column lets an emulation epoch's state stay alive while KeyPackages
-- derived from it can still be welcomed.
CREATE TABLE vc_retained_key_package_material (
    provider_version INTEGER NOT NULL,
    key_package_ref BLOB NOT NULL,
    epoch_id BLOB NOT NULL,
    record BLOB NOT NULL,
    PRIMARY KEY (key_package_ref)
);

CREATE INDEX vc_retained_key_package_material_epoch_id
    ON vc_retained_key_package_material (epoch_id);
