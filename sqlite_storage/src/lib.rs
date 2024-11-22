// SPDX-FileCopyrightText: 2023 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

mod codec;
mod encryption_key_pairs;
mod epoch_key_pairs;
mod group_data;
mod key_packages;
mod own_leaf_nodes;
mod proposals;
mod psks;
mod signature_key_pairs;
mod storage_provider;
mod wrappers;

pub use codec::{Codec, JsonCodec};
pub use storage_provider::SqliteStorageProvider;

trait Storable {
    const CREATE_TABLE_STATEMENT: &'static str;

    fn from_row<C: Codec>(row: &rusqlite::Row) -> Result<Self, rusqlite::Error>
    where
        Self: Sized;
}
