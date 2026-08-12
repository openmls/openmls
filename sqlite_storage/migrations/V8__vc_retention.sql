-- Each of the three entities below gets its own table rather than riding the
-- generic `group_data` table with a type discriminator. That follows the local
-- virtual-clients precedent: V4 gave the emulation bindings their own table and
-- V6 did the same for the registered derivation epochs. The reference index is
-- keyed on a derivation epoch rather than on a group id, which `group_data`
-- cannot express at all.

-- Virtual-clients retention state of an emulation group. One row per emulation
-- group, holding the serialized log of retained derivation epochs, the
-- per-member watermarks and latest declarations, the obligations assumed for
-- removed clients, and the application's own epoch references. It is one blob
-- because a commit installs a member's watermark and its declaration together.
CREATE TABLE vc_retention_states (
    provider_version INTEGER NOT NULL,
    group_id BLOB NOT NULL,
    retention_state BLOB NOT NULL,
    PRIMARY KEY (group_id)
);

-- Reverse reference index of a derivation epoch. One row per derivation epoch,
-- holding the serialized set of higher-level groups that hold the epoch through
-- a pending commit, an active leaf binding, or an unacknowledged group
-- creation. Those references live keyed by higher-level group, which a reaper
-- working per emulation group cannot enumerate.
CREATE TABLE vc_epoch_refs (
    provider_version INTEGER NOT NULL,
    epoch_id BLOB NOT NULL,
    epoch_refs BLOB NOT NULL,
    PRIMARY KEY (epoch_id)
);

-- Creation tracking of a higher-level group. One row per higher-level group,
-- holding the serialized derivation epoch the group was created or externally
-- joined from and the emulation-group members that have not been seen
-- committing in that group yet. The epoch stays retained until the outstanding
-- set empties.
CREATE TABLE vc_creation_tracking (
    provider_version INTEGER NOT NULL,
    group_id BLOB NOT NULL,
    creation_tracking BLOB NOT NULL,
    PRIMARY KEY (group_id)
);
