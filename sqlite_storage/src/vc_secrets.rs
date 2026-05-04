use std::marker::PhantomData;

use openmls_traits::storage::{
    traits::VcEpochBaseSecret as VcEpochBaseSecretTrait,
    traits::VcEpochEncryptionKey as VcEpochEncryptionKeyTrait, traits::VcEpochId as VcEpochIdTrait,
    Entity as EntityTrait, Key,
};
use rusqlite::{params, OptionalExtension as _, ToSql};

use crate::{
    storage_provider::StorableKeyRef,
    wrappers::{EntityRefWrapper, EntityWrapper, KeyRefWrapper},
    Codec, STORAGE_PROVIDER_VERSION,
};

enum SecretType {
    EpochBaseSecret,
    EpochEncryptionKey,
}

impl ToSql for SecretType {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        let secret_type_str = match self {
            SecretType::EpochBaseSecret => "epoch_base_secret",
            SecretType::EpochEncryptionKey => "epoch_encryption_key",
        };
        Ok(rusqlite::types::ToSqlOutput::Borrowed(
            rusqlite::types::ValueRef::Text(secret_type_str.as_bytes()),
        ))
    }
}

pub(super) struct StorableEntityRef<'a, Entity: EntityTrait<STORAGE_PROVIDER_VERSION>>(
    pub &'a Entity,
);

impl<'a, VcEpochEncryptionKey: VcEpochEncryptionKeyTrait<STORAGE_PROVIDER_VERSION>>
    StorableEntityRef<'a, VcEpochEncryptionKey>
{
    pub(super) fn store_vc_encryption_key<C: Codec, EpochId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        connection: &rusqlite::Connection,
        epoch_id: &EpochId,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO vc_emulation_group_secrets (provider_version, epoch_id, secret_type, vc_secret)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(epoch_id, secret_type) DO UPDATE SET
                vc_secret = excluded.vc_secret",
            params![
                STORAGE_PROVIDER_VERSION,
                KeyRefWrapper::<C, _>(epoch_id, PhantomData),
                SecretType::EpochEncryptionKey,
                EntityRefWrapper::<C, _>(self.0, PhantomData)
            ],
        )?;
        Ok(())
    }
}

impl<'a, VcEpochBaseSecret: VcEpochBaseSecretTrait<STORAGE_PROVIDER_VERSION>>
    StorableEntityRef<'a, VcEpochBaseSecret>
{
    pub(super) fn store_vc_base_secret<C: Codec, EpochId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        connection: &rusqlite::Connection,
        epoch_id: &EpochId,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO vc_emulation_group_secrets (provider_version, epoch_id, secret_type, vc_secret)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(epoch_id, secret_type) DO UPDATE SET
                vc_secret = excluded.vc_secret",
            params![
                STORAGE_PROVIDER_VERSION,
                KeyRefWrapper::<C, _>(epoch_id, PhantomData),
                SecretType::EpochBaseSecret,
                EntityRefWrapper::<C, _>(self.0, PhantomData)
            ],
        )?;
        Ok(())
    }
}

impl<VcEpochId: VcEpochIdTrait<STORAGE_PROVIDER_VERSION>> StorableKeyRef<'_, VcEpochId> {
    pub(super) fn load_vc_encryption_key<
        C: Codec,
        VcEpochEncryptionKey: VcEpochEncryptionKeyTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<Option<VcEpochEncryptionKey>, rusqlite::Error> {
        let Self(epoch_id) = self;
        let mut stmt = connection.prepare(
            "SELECT vc_secret
            FROM vc_emulation_group_secrets
            WHERE epoch_id = ?1
                AND provider_version = ?2
                AND secret_type = ?3",
        )?;
        stmt.query_row(
            params![
                KeyRefWrapper::<C, VcEpochId>(epoch_id, PhantomData),
                STORAGE_PROVIDER_VERSION,
                SecretType::EpochEncryptionKey
            ],
            |row| {
                let EntityWrapper::<C, VcEpochEncryptionKey>(epoch_encryption_key, ..) =
                    row.get(0)?;
                Ok(epoch_encryption_key)
            },
        )
        .optional()
    }

    pub(super) fn delete_vc_encryption_key<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<(), rusqlite::Error> {
        let Self(epoch_id) = self;
        connection.execute(
            "DELETE FROM vc_emulation_group_secrets
            WHERE epoch_id = ?1
                AND provider_version = ?2
                AND secret_type = ?3",
            params![
                KeyRefWrapper::<C, VcEpochId>(epoch_id, PhantomData),
                STORAGE_PROVIDER_VERSION,
                SecretType::EpochEncryptionKey
            ],
        )?;
        Ok(())
    }

    pub(super) fn load_vc_base_secret<
        C: Codec,
        VcEpochBaseSecret: VcEpochBaseSecretTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<Option<VcEpochBaseSecret>, rusqlite::Error> {
        let Self(epoch_id) = self;
        let mut stmt = connection.prepare(
            "SELECT vc_secret
            FROM vc_emulation_group_secrets
            WHERE epoch_id = ?1
                AND provider_version = ?2
                AND secret_type = ?3",
        )?;
        stmt.query_row(
            params![
                KeyRefWrapper::<C, VcEpochId>(epoch_id, PhantomData),
                STORAGE_PROVIDER_VERSION,
                SecretType::EpochBaseSecret
            ],
            |row| {
                let EntityWrapper::<C, VcEpochBaseSecret>(epoch_base_secret, ..) = row.get(0)?;
                Ok(epoch_base_secret)
            },
        )
        .optional()
    }

    pub(super) fn delete_vc_base_secret<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<(), rusqlite::Error> {
        let Self(epoch_id) = self;
        connection.execute(
            "DELETE FROM vc_emulation_group_secrets
            WHERE epoch_id = ?1
                AND provider_version = ?2
                AND secret_type = ?3",
            params![
                KeyRefWrapper::<C, VcEpochId>(epoch_id, PhantomData),
                STORAGE_PROVIDER_VERSION,
                SecretType::EpochBaseSecret
            ],
        )?;
        Ok(())
    }
}
