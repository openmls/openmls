use std::marker::PhantomData;

use openmls_traits::storage::{Entity, Key};
use rusqlite::{Connection, OptionalExtension, params};

use crate::{
    STORAGE_PROVIDER_VERSION,
    codec::Codec,
    wrappers::{EntityRefWrapper, EntityWrapper, KeyRefWrapper},
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
    ) -> Result<Option<EncryptionKeyPair>, rusqlite::Error> {
        connection
            .query_row(
                "SELECT key_pair FROM openmls_encryption_keys WHERE public_key = ?1 AND provider_version = ?2",
                params![KeyRefWrapper::<C, _>(public_key, PhantomData), STORAGE_PROVIDER_VERSION],
                Self::from_row::<C>,
            )
            .map(|x| x.0)
            .optional()
    }

    pub(super) fn load_in_tx<C: Codec, EncryptionKey: Key<STORAGE_PROVIDER_VERSION>>(
        tx: &rusqlite::Transaction<'_>,
        public_key: &EncryptionKey,
    ) -> Result<Option<EncryptionKeyPair>, rusqlite::Error> {
        let mut stmt = tx.prepare_cached(
            "SELECT key_pair FROM openmls_encryption_keys WHERE public_key = ?1 AND provider_version = ?2",
        )?;
        stmt.query_row(
            params![
                KeyRefWrapper::<C, _>(public_key, PhantomData),
                STORAGE_PROVIDER_VERSION
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
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = connection.prepare_cached(
            "INSERT OR REPLACE INTO openmls_encryption_keys (public_key, key_pair, provider_version)
            VALUES (?1, ?2, ?3)",
        )?;
        stmt.execute(params![
            KeyRefWrapper::<C, _>(public_key, PhantomData),
            EntityRefWrapper::<C, _>(self.0, PhantomData),
            STORAGE_PROVIDER_VERSION
        ])?;
        Ok(())
    }

    pub(super) fn store_in_tx<C: Codec, EncryptionKey: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        tx: &rusqlite::Transaction<'_>,
        public_key: &EncryptionKey,
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = tx.prepare_cached(
            "INSERT OR REPLACE INTO openmls_encryption_keys (public_key, key_pair, provider_version)
            VALUES (?1, ?2, ?3)",
        )?;
        stmt.execute(params![
            KeyRefWrapper::<C, _>(public_key, PhantomData),
            EntityRefWrapper::<C, _>(self.0, PhantomData),
            STORAGE_PROVIDER_VERSION
        ])?;
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
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = connection.prepare_cached(
            "DELETE FROM openmls_encryption_keys WHERE public_key = ?1 AND provider_version = ?2",
        )?;
        stmt.execute(params![
            KeyRefWrapper::<C, _>(self.0, PhantomData),
            STORAGE_PROVIDER_VERSION
        ])?;
        Ok(())
    }

    pub(super) fn delete_in_tx<C: Codec>(
        &self,
        tx: &rusqlite::Transaction<'_>,
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = tx.prepare_cached(
            "DELETE FROM openmls_encryption_keys WHERE public_key = ?1 AND provider_version = ?2",
        )?;
        stmt.execute(params![
            KeyRefWrapper::<C, _>(self.0, PhantomData),
            STORAGE_PROVIDER_VERSION
        ])?;
        Ok(())
    }
}
