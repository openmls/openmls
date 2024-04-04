use openmls_traits::storage::{
    DeleteError as StorageDeleteError, GetError as StorageGetError,
    InsertError as StorageInsertError, Key, Platform,
};

#[derive(Clone, Debug)]
pub enum GetError<'a, InnerError> {
    InternalError(InnerError),
    NotFound(&'a [u8]),
}

impl<'a, T> GetError<'a, T> {
    pub fn into_storage_error(
        key: Key,
    ) -> impl (FnOnce(Self) -> StorageGetError<T, serde_json::Error>) {
        move |kv_err| match kv_err {
            GetError::InternalError(e) => StorageGetError::InternalError(e),
            GetError::NotFound(_) => StorageGetError::NotFound(key),
        }
    }
}

#[derive(Clone, Debug)]
pub enum DeleteError<'a, InnerError> {
    InternalError(InnerError),
    NotFound(&'a [u8]),
}

impl<'a, T> DeleteError<'a, T> {
    pub fn into_storage_error(
        key: Key,
    ) -> impl (FnOnce(DeleteError<T>) -> StorageDeleteError<T, serde_json::Error>) {
        move |kv_err| match kv_err {
            DeleteError::InternalError(e) => StorageDeleteError::InternalError(e),
            DeleteError::NotFound(_) => StorageDeleteError::NotFound(key),
        }
    }
}
#[derive(Clone, Debug)]
pub enum InsertError<InnerError> {
    InternalError(InnerError),
    AlreadyExists(Vec<u8>),
}
impl<T> InsertError<T> {
    pub fn into_storage_error(
        key: Key,
    ) -> impl (FnOnce(Self) -> StorageInsertError<T, serde_json::Error>) {
        move |kv_err| match kv_err {
            InsertError::InternalError(e) => StorageInsertError::InternalError(e),
            InsertError::AlreadyExists(_) => StorageInsertError::AlreadyExists(key),
        }
    }
}

pub trait KeyValueStore: Platform {
    fn get<'a>(&self, key: &'a [u8]) -> Result<Vec<u8>, GetError<'a, Self::InternalError>>;
    fn insert(
        &mut self,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<(), InsertError<Self::InternalError>>;
    fn delete<'a>(&mut self, key: &'a [u8]) -> Result<(), DeleteError<'a, Self::InternalError>>;
}

use std::collections::HashMap;

#[derive(Default, Debug, Clone)]
pub struct HashMapKV(HashMap<Vec<u8>, Vec<u8>>);

impl openmls_traits::storage::Platform for HashMapKV {
    type InternalError = ();
    type SerializeError = serde_json::Error;
}

impl KeyValueStore for HashMapKV {
    fn get<'a>(&self, key: &'a [u8]) -> Result<Vec<u8>, GetError<'a, Self::InternalError>> {
        HashMap::get(&self.0, key)
            .ok_or(GetError::NotFound(key))
            .cloned()
    }

    fn insert(
        &mut self,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<(), InsertError<Self::InternalError>> {
        match HashMap::insert(&mut self.0, key.clone(), value) {
            Some(old_value) => {
                HashMap::insert(&mut self.0, key.clone(), old_value);
                Err(InsertError::AlreadyExists(key))
            }
            None => Ok(()),
        }
    }

    fn delete<'a>(&mut self, key: &'a [u8]) -> Result<(), DeleteError<'a, Self::InternalError>> {
        HashMap::remove(&mut self.0, key)
            .ok_or(DeleteError::NotFound(key))
            .map(|_| ())
    }
}
