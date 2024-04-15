pub use super::kv_store::*;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct HashMapKv(std::collections::HashMap<Vec<u8>, Vec<u8>>);

#[derive(Debug, Clone, PartialEq)]
pub enum Infallible {}

impl core::fmt::Display for Infallible {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unreachable!()
    }
}

impl std::error::Error for Infallible {}

impl KvStore for HashMapKv {
    type InternalError = Infallible;

    fn get(&self, key: &[u8]) -> Result<Vec<u8>, KvGetError<Infallible>> {
        self.0
            .get(key)
            .cloned()
            .ok_or(KvGetError::NotFound(key.to_vec()))
    }

    fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), KvInsertError<Infallible>> {
        match self.0.insert(key.clone(), value) {
            Some(old_value) => Err(KvInsertError::AlreadyExists(key, old_value)),
            None => Ok(()),
        }
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), KvDeleteError<Infallible>> {
        match self.0.remove(key) {
            Some(_) => Ok(()),
            None => Err(KvDeleteError::NotFound(key.to_vec())),
        }
    }
}
