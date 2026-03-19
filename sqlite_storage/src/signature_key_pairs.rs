use std::marker::PhantomData;

use openmls_traits::storage::{traits::SignaturePublicKey as SignaturePublicKeyTrait, Entity, Key};
use rusqlite::{params, Connection, OptionalExtension};

use crate::{
    codec::Codec,
    wrappers::{EntityRefWrapper, EntityWrapper, KeyRefWrapper},
    STORAGE_PROVIDER_VERSION,
};

pub(crate) struct StorableSignatureKeyPairs<SignatureKeyPairs: Entity<STORAGE_PROVIDER_VERSION>>(
    pub SignatureKeyPairs,
);

impl<SignatureKeyPairs: Entity<STORAGE_PROVIDER_VERSION>>
    StorableSignatureKeyPairs<SignatureKeyPairs>
{
    pub(super) fn load<
        C: Codec,
        SignaturePublicKey: SignaturePublicKeyTrait<STORAGE_PROVIDER_VERSION>,
    >(
        connection: &Connection,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPairs>, rusqlite::Error> {
        let signature_key = connection
            .query_row(
                "SELECT signature_key
                FROM openmls_signature_keys
                WHERE public_key = ?1
                    AND provider_version = ?2",
                params![
                    KeyRefWrapper::<C, _>(public_key, PhantomData),
                    STORAGE_PROVIDER_VERSION
                ],
                |row| {
                    let EntityWrapper::<C, _>(signature_key, ..) = row.get(0)?;
                    Ok(signature_key)
                },
            )
            .optional()?;
        Ok(signature_key)
    }

    pub(super) fn load_in_tx<
        C: Codec,
        SignaturePublicKey: SignaturePublicKeyTrait<STORAGE_PROVIDER_VERSION>,
    >(
        tx: &rusqlite::Transaction<'_>,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPairs>, rusqlite::Error> {
        let mut stmt = tx.prepare_cached(
            "SELECT signature_key
                FROM openmls_signature_keys
                WHERE public_key = ?1
                    AND provider_version = ?2",
        )?;
        let signature_key = stmt
            .query_row(
                params![
                    KeyRefWrapper::<C, _>(public_key, PhantomData),
                    STORAGE_PROVIDER_VERSION
                ],
                |row| {
                    let EntityWrapper::<C, _>(signature_key, ..) = row.get(0)?;
                    Ok(signature_key)
                },
            )
            .optional()?;
        Ok(signature_key)
    }
}

pub(crate) struct StorableSignatureKeyPairsRef<
    'a,
    SignatureKeyPairs: Entity<STORAGE_PROVIDER_VERSION>,
>(pub &'a SignatureKeyPairs);

impl<SignatureKeyPairs: Entity<STORAGE_PROVIDER_VERSION>>
    StorableSignatureKeyPairsRef<'_, SignatureKeyPairs>
{
    pub(super) fn store<C: Codec, SignaturePublicKey: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        connection: &Connection,
        public_key: &SignaturePublicKey,
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = connection.prepare_cached(
            "INSERT OR REPLACE INTO openmls_signature_keys (public_key, signature_key, provider_version)
            VALUES (?1, ?2, ?3)",
        )?;
        stmt.execute(params![
            KeyRefWrapper::<C, _>(public_key, PhantomData),
            EntityRefWrapper::<C, _>(self.0, PhantomData),
            STORAGE_PROVIDER_VERSION
        ])?;
        Ok(())
    }

    pub(super) fn store_in_tx<C: Codec, SignaturePublicKey: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        tx: &rusqlite::Transaction<'_>,
        public_key: &SignaturePublicKey,
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = tx.prepare_cached(
            "INSERT OR REPLACE INTO openmls_signature_keys (public_key, signature_key, provider_version)
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

pub(super) struct StorableSignaturePublicKeyRef<
    'a,
    SignaturePublicKey: Key<STORAGE_PROVIDER_VERSION>,
>(pub &'a SignaturePublicKey);

impl<SignaturePublicKey: Key<STORAGE_PROVIDER_VERSION>>
    StorableSignaturePublicKeyRef<'_, SignaturePublicKey>
{
    pub(super) fn delete<C: Codec>(&self, connection: &Connection) -> Result<(), rusqlite::Error> {
        let mut stmt = connection.prepare_cached(
            "DELETE FROM openmls_signature_keys
            WHERE public_key = ?1
                AND provider_version = ?2",
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
            "DELETE FROM openmls_signature_keys
            WHERE public_key = ?1
                AND provider_version = ?2",
        )?;
        stmt.execute(params![
            KeyRefWrapper::<C, _>(self.0, PhantomData),
            STORAGE_PROVIDER_VERSION
        ])?;
        Ok(())
    }
}
