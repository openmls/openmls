// SPDX-FileCopyrightText: 2023 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls_traits::storage::{CURRENT_VERSION, Entity, Key};

pub(crate) struct StorableKeyPackage<KeyPackage: Entity<CURRENT_VERSION>>(pub KeyPackage);

pub(super) struct StorableKeyPackageRef<'a, KeyPackage: Entity<CURRENT_VERSION>>(
    pub &'a KeyPackage,
);

pub(super) struct StorableHashRef<'a, KeyPackageRef: Key<CURRENT_VERSION>>(pub &'a KeyPackageRef);
