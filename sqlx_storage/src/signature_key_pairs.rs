// SPDX-FileCopyrightText: 2023 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls_traits::storage::{CURRENT_VERSION, Entity, Key};

pub(crate) struct StorableSignatureKeyPairs<SignatureKeyPairs: Entity<CURRENT_VERSION>>(
    pub SignatureKeyPairs,
);

pub(crate) struct StorableSignatureKeyPairsRef<'a, SignatureKeyPairs: Entity<CURRENT_VERSION>>(
    pub &'a SignatureKeyPairs,
);

pub(super) struct StorableSignaturePublicKeyRef<'a, SignaturePublicKey: Key<CURRENT_VERSION>>(
    pub &'a SignaturePublicKey,
);
