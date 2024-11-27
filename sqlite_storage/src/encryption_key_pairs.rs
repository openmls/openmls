use std::marker::PhantomData;

use openmls_traits::storage::{Entity, Key};
use rusqlite::{params, OptionalExtension};

use crate::{
    codec::Codec,
    wrappers::{EntityRefWrapper, EntityWrapper, KeyRefWrapper},
};

pub(crate) struct StorableEncryptionKeyPair<EncryptionKeyPair: Entity<1>>(pub EncryptionKeyPair);

impl<EncryptionKeyPair: Entity<1>> StorableEncryptionKeyPair<EncryptionKeyPair> {
    fn from_row<C: Codec>(row: &rusqlite::Row) -> Result<Self, rusqlite::Error> {
        let EntityWrapper::<C, _>(encryption_key_pair, ..) = row.get(0)?;
        Ok(Self(encryption_key_pair))
    }

    pub(super) fn load<C: Codec, EncryptionKey: Key<1>>(
        connection: &rusqlite::Connection,
        public_key: &EncryptionKey,
    ) -> Result<Option<EncryptionKeyPair>, rusqlite::Error> {
        connection
            .query_row(
                "SELECT key_pair FROM openmls_encryption_keys WHERE public_key = ?1",
                params![KeyRefWrapper::<C, _>(public_key, PhantomData)],
                Self::from_row::<C>,
            )
            .map(|x| x.0)
            .optional()
    }
}

pub(crate) struct StorableEncryptionKeyPairRef<'a, EncryptionKeyPair: Entity<1>>(
    pub &'a EncryptionKeyPair,
);

impl<'a, EncryptionKeyPair: Entity<1>> StorableEncryptionKeyPairRef<'a, EncryptionKeyPair> {
    pub(super) fn store<C: Codec, EncryptionKey: Key<1>>(
        &self,
        connection: &rusqlite::Connection,
        public_key: &EncryptionKey,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO openmls_encryption_keys (public_key, key_pair) VALUES (?1, ?2)",
            params![
                KeyRefWrapper::<C, _>(public_key, PhantomData),
                EntityRefWrapper::<C, _>(self.0, PhantomData)
            ],
        )?;
        Ok(())
    }
}

pub(crate) struct StorableEncryptionPublicKeyRef<'a, EncryptionPublicKey: Key<1>>(
    pub &'a EncryptionPublicKey,
);

impl<'a, EncryptionPublicKey: Key<1>> StorableEncryptionPublicKeyRef<'a, EncryptionPublicKey> {
    pub(super) fn delete<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "DELETE FROM openmls_encryption_keys WHERE public_key = ?1",
            params![KeyRefWrapper::<C, _>(self.0, PhantomData)],
        )?;
        Ok(())
    }
}
