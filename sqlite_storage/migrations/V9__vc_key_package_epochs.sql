-- The derivation epoch a published virtual-client KeyPackage was built from.
-- One row per KeyPackage reference, written when the publishing client
-- finalizes a batch and deleted together with the KeyPackage. The epoch_id
-- column keeps a derivation epoch's state alive while a Welcome for one of its
-- KeyPackages can still arrive, which is the publishing-side counterpart of the
-- epoch_id column on vc_retained_key_package_material.
CREATE TABLE vc_key_package_epochs (
    provider_version INTEGER NOT NULL,
    key_package_ref BLOB NOT NULL,
    epoch_id BLOB NOT NULL,
    PRIMARY KEY (key_package_ref)
);

CREATE INDEX vc_key_package_epochs_epoch_id
    ON vc_key_package_epochs (epoch_id);
