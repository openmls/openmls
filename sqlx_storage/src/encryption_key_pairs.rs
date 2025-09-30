// SPDX-FileCopyrightText: 2023 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls_traits::storage::{CURRENT_VERSION, Entity, Key};

pub(crate) struct StorableEncryptionKeyPair<EncryptionKeyPair: Entity<CURRENT_VERSION>>(
    pub EncryptionKeyPair,
);

pub(crate) struct StorableEncryptionKeyPairRef<'a, EncryptionKeyPair: Entity<CURRENT_VERSION>>(
    pub &'a EncryptionKeyPair,
);

pub(crate) struct StorableEncryptionPublicKeyRef<'a, EncryptionPublicKey: Key<CURRENT_VERSION>>(
    pub &'a EncryptionPublicKey,
);
