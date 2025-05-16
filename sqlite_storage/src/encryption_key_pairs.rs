use std::marker::PhantomData;

use openmls_traits::storage::{Entity, Key};
use rusqlite::{params, Connection, OptionalExtension};

use crate::{
    codec::Codec,
    wrappers::{EntityRefWrapper, EntityWrapper, KeyRefWrapper},
    STORAGE_PROVIDER_VERSION,
};

pub(crate) struct StorableEncryptionKeyPair<EncryptionKeyPair: Entity<STORAGE_PROVIDER_VERSION>>(
    pub EncryptionKeyPair,
);

impl<EncryptionKeyPair: Entity<STORAGE_PROVIDER_VERSION>>
    StorableEncryptionKeyPair<EncryptionKeyPair>
{
    fn from_row<C: Codec>(row: &rusqlite::Row) -> Result<Self, rusqlite::Error> {
        let EntityWrapper::<C, _>(encryption_key_pair, ..) = row.get(0)?;
        Ok(Self(encryption_key_pair))
    }

    pub(super) fn load<C: Codec, EncryptionKey: Key<STORAGE_PROVIDER_VERSION>>(
        connection: &Connection,
        public_key: &EncryptionKey,
        epoch_id: &[u8],
    ) -> Result<Option<EncryptionKeyPair>, rusqlite::Error> {
        connection
            .query_row(
                "SELECT key_pair 
                FROM openmls_encryption_keys 
                WHERE public_key = ?1 
                    AND provider_version = ?2 
                    AND dmls_epoch_id = ?3",
                params![
                    KeyRefWrapper::<C, _>(public_key, PhantomData),
                    STORAGE_PROVIDER_VERSION,
                    epoch_id
                ],
                Self::from_row::<C>,
            )
            .map(|x| x.0)
            .optional()
    }
}

pub(crate) struct StorableEncryptionKeyPairRef<
    'a,
    EncryptionKeyPair: Entity<STORAGE_PROVIDER_VERSION>,
>(pub &'a EncryptionKeyPair);

impl<EncryptionKeyPair: Entity<STORAGE_PROVIDER_VERSION>>
    StorableEncryptionKeyPairRef<'_, EncryptionKeyPair>
{
    pub(super) fn store<C: Codec, EncryptionKey: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        connection: &Connection,
        public_key: &EncryptionKey,
        epoch_id: &[u8],
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO openmls_encryption_keys (public_key, key_pair, provider_version, dmls_epoch_id) 
            VALUES (?1, ?2, ?3, ?4)",
            params![
                KeyRefWrapper::<C, _>(public_key, PhantomData),
                EntityRefWrapper::<C, _>(self.0, PhantomData),
                STORAGE_PROVIDER_VERSION,
                epoch_id
            ],
        )?;
        Ok(())
    }
}

pub(crate) struct StorableEncryptionPublicKeyRef<
    'a,
    EncryptionPublicKey: Key<STORAGE_PROVIDER_VERSION>,
>(pub &'a EncryptionPublicKey);

impl<EncryptionPublicKey: Key<STORAGE_PROVIDER_VERSION>>
    StorableEncryptionPublicKeyRef<'_, EncryptionPublicKey>
{
    pub(super) fn delete<C: Codec>(
        &self,
        connection: &Connection,
        epoch_id: &[u8],
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "DELETE FROM openmls_encryption_keys 
            WHERE public_key = ?1 
                AND provider_version = ?2 
                AND dmls_epoch_id = ?3",
            params![
                KeyRefWrapper::<C, _>(self.0, PhantomData),
                STORAGE_PROVIDER_VERSION,
                epoch_id
            ],
        )?;
        Ok(())
    }
}
