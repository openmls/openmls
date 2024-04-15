pub trait KvStore: core::fmt::Debug {
    type InternalError: core::fmt::Debug + PartialEq + std::error::Error;

    fn get(&self, key: &[u8]) -> Result<Vec<u8>, KvGetError<Self::InternalError>>;
    fn insert(
        &mut self,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<(), KvInsertError<Self::InternalError>>;
    fn delete(&mut self, key: &[u8]) -> Result<(), KvDeleteError<Self::InternalError>>;
}

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Error)]
pub enum KvGetError<InternalError> {
    #[error("key {0:?} not found")]
    NotFound(Vec<u8>),
    #[error("internal error: {0:?}")]
    Internal(InternalError),
}

#[derive(Debug, Clone, PartialEq, Error)]
pub enum KvInsertError<InternalError> {
    #[error("entry with key {0:?} already exists")]
    AlreadyExists(Vec<u8>, Vec<u8>),
    #[error("internal error: {0:?}")]
    Internal(InternalError),
}

#[derive(Debug, Clone, PartialEq, Error)]
pub enum KvDeleteError<InternalError> {
    #[error("key {0:?} not found")]
    NotFound(Vec<u8>),
    #[error("internal error: {0:?}")]
    Internal(InternalError),
}
