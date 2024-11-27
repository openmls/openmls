use std::marker::PhantomData;

use openmls_traits::storage::{Entity, Key};
use rusqlite::{
    types::{FromSql, ToSqlOutput},
    ToSql,
};
use serde::Serialize;

use crate::codec::Codec;

#[derive(Debug, Serialize)]
pub(super) struct KeyRefWrapper<'a, C: Codec, T: Key<1>>(pub &'a T, pub PhantomData<C>);

impl<C: Codec, T: Key<1>> ToSql for KeyRefWrapper<'_, C, T> {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        let key_bytes =
            C::to_vec(&self.0).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        Ok(ToSqlOutput::Owned(rusqlite::types::Value::Blob(key_bytes)))
    }
}

pub(super) struct EntityWrapper<C: Codec, T: Entity<1>>(pub T, pub PhantomData<C>);

impl<C: Codec, T: Entity<1>> FromSql for EntityWrapper<C, T> {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        let entity = C::from_slice(value.as_blob()?)
            .map_err(|e| rusqlite::types::FromSqlError::Other(Box::new(e)))?;
        Ok(Self(entity, PhantomData))
    }
}

pub(super) struct EntityRefWrapper<'a, C: Codec, T: Entity<1>>(pub &'a T, pub PhantomData<C>);

impl<'a, C: Codec, T: Entity<1>> ToSql for EntityRefWrapper<'a, C, T> {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        let entity_bytes =
            C::to_vec(&self.0).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        Ok(ToSqlOutput::Owned(rusqlite::types::Value::Blob(
            entity_bytes,
        )))
    }
}

pub(super) struct EntitySliceWrapper<'a, C: Codec, T: Entity<1>>(pub &'a [T], pub PhantomData<C>);

impl<'a, C: Codec, T: Entity<1>> ToSql for EntitySliceWrapper<'a, C, T> {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        let entity_bytes =
            C::to_vec(&self.0).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        Ok(ToSqlOutput::Owned(rusqlite::types::Value::Blob(
            entity_bytes,
        )))
    }
}

pub(super) struct EntityVecWrapper<C: Codec, T: Entity<1>>(pub Vec<T>, pub PhantomData<C>);

impl<C: Codec, T: Entity<1>> FromSql for EntityVecWrapper<C, T> {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        let entities = C::from_slice(value.as_blob()?)
            .map_err(|e| rusqlite::types::FromSqlError::Other(Box::new(e)))?;
        Ok(Self(entities, PhantomData))
    }
}
