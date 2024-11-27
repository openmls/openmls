use std::marker::PhantomData;

use openmls_traits::storage::{traits::SignaturePublicKey as SignaturePublicKeyTrait, Entity, Key};
use rusqlite::{params, OptionalExtension};

use crate::{
    codec::Codec,
    wrappers::{EntityRefWrapper, EntityWrapper, KeyRefWrapper},
};

pub(crate) struct StorableSignatureKeyPairs<SignatureKeyPairs: Entity<1>>(pub SignatureKeyPairs);

impl<SignatureKeyPairs: Entity<1>> StorableSignatureKeyPairs<SignatureKeyPairs> {
    pub(super) fn load<C: Codec, SignaturePublicKey: SignaturePublicKeyTrait<1>>(
        connection: &rusqlite::Connection,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPairs>, rusqlite::Error> {
        let signature_key = connection
            .query_row(
                "SELECT signature_key FROM openmls_signature_keys WHERE public_key = ?1",
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

pub(crate) struct StorableSignatureKeyPairsRef<'a, SignatureKeyPairs: Entity<1>>(
    pub &'a SignatureKeyPairs,
);

impl<'a, SignatureKeyPairs: Entity<1>> StorableSignatureKeyPairsRef<'a, SignatureKeyPairs> {
    pub(super) fn store<C: Codec, SignaturePublicKey: Key<1>>(
        &self,
        connection: &rusqlite::Connection,
        public_key: &SignaturePublicKey,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO openmls_signature_keys (public_key, signature_key) VALUES (?1, ?2)",
            params![
                KeyRefWrapper::<C, _>(public_key, PhantomData),
                EntityRefWrapper::<C, _>(self.0, PhantomData)
            ],
        )?;
        Ok(())
    }
}

pub(super) struct StorableSignaturePublicKeyRef<'a, SignaturePublicKey: Key<1>>(
    pub &'a SignaturePublicKey,
);

impl<'a, SignaturePublicKey: Key<1>> StorableSignaturePublicKeyRef<'a, SignaturePublicKey> {
    pub(super) fn delete<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "DELETE FROM openmls_signature_keys WHERE public_key = ?1",
            params![KeyRefWrapper::<C, _>(self.0, PhantomData)],
        )?;
        Ok(())
    }
}
