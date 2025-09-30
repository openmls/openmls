// SPDX-FileCopyrightText: 2023 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls_traits::storage::{CURRENT_VERSION, Entity, Key};

pub(crate) struct StorablePskBundle<PskBundle: Entity<CURRENT_VERSION>>(PskBundle);

pub(super) struct StorablePskBundleRef<'a, PskBundle: Entity<CURRENT_VERSION>>(pub &'a PskBundle);

pub(super) struct StorablePskIdRef<'a, PskId: Key<CURRENT_VERSION>>(pub &'a PskId);
