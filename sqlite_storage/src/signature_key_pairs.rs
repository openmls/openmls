use std::marker::PhantomData;

use openmls_traits::storage::{
    traits::SignaturePublicKey as SignaturePublicKeyTrait, Entity, Key, CURRENT_VERSION,
};
use rusqlite::{params, OptionalExtension};

use crate::{
    codec::Codec,
    wrappers::{EntityRefWrapper, EntityWrapper, KeyRefWrapper},
    Storable,
};

pub(crate) struct StorableSignatureKeyPairs<SignatureKeyPairs: Entity<CURRENT_VERSION>>(
    pub SignatureKeyPairs,
);

impl<SignatureKeyPairs: Entity<CURRENT_VERSION>> Storable
    for StorableSignatureKeyPairs<SignatureKeyPairs>
{
    const CREATE_TABLE_STATEMENT: &'static str = "CREATE TABLE IF NOT EXISTS signature_keys (
        public_key BLOB PRIMARY KEY,
        signature_key BLOB NOT NULL
    );";

    fn from_row<C: Codec>(row: &rusqlite::Row) -> Result<Self, rusqlite::Error> {
        let EntityWrapper::<C, _>(signature_key_pairs, ..) = row.get(0)?;
        Ok(Self(signature_key_pairs))
    }
}

pub(crate) struct StorableSignatureKeyPairsRef<'a, SignatureKeyPairs: Entity<CURRENT_VERSION>>(
    pub &'a SignatureKeyPairs,
);

impl<'a, SignatureKeyPairs: Entity<CURRENT_VERSION>>
    StorableSignatureKeyPairsRef<'a, SignatureKeyPairs>
{
    pub(super) fn store<C: Codec, SignaturePublicKey: Key<CURRENT_VERSION>>(
        &self,
        connection: &rusqlite::Connection,
        public_key: &SignaturePublicKey,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO signature_keys (public_key, signature_key) VALUES (?1, ?2)",
            params![
                KeyRefWrapper::<C, _>(public_key, PhantomData),
                EntityRefWrapper::<C, _>(self.0, PhantomData)
            ],
        )?;
        Ok(())
    }
}
impl<SignatureKeyPairs: Entity<CURRENT_VERSION>> StorableSignatureKeyPairs<SignatureKeyPairs> {
    pub(super) fn load<C: Codec, SignaturePublicKey: SignaturePublicKeyTrait<CURRENT_VERSION>>(
        connection: &rusqlite::Connection,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPairs>, rusqlite::Error> {
        let signature_key = connection
            .query_row(
                "SELECT signature_key FROM signature_keys WHERE public_key = ?1",
                params![KeyRefWrapper::<C, _>(public_key, PhantomData)],
                |row| {
                    let EntityWrapper::<C, _>(signature_key, ..) = row.get(0)?;
                    Ok(signature_key)
                },
            )
            .optional()?;
        Ok(signature_key)
    }
}

pub(super) struct StorableSignaturePublicKeyRef<'a, SignaturePublicKey: Key<CURRENT_VERSION>>(
    pub &'a SignaturePublicKey,
);

impl<'a, SignaturePublicKey: Key<CURRENT_VERSION>>
    StorableSignaturePublicKeyRef<'a, SignaturePublicKey>
{
    pub(super) fn delete<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "DELETE FROM signature_keys WHERE public_key = ?1",
            params![KeyRefWrapper::<C, _>(self.0, PhantomData)],
        )?;
        Ok(())
    }
}
