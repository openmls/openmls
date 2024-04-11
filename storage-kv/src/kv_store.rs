pub trait KvStore {
    type InternalError: core::fmt::Debug;

    fn get(&self, key: &[u8]) -> Result<Vec<u8>, KvGetError<Self::InternalError>>;
    fn insert(
        &mut self,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<(), KvInsertError<Self::InternalError>>;
    fn delete(&mut self, key: &[u8]) -> Result<(), KvDeleteError<Self::InternalError>>;
}

#[derive(Debug)]
pub enum Infallible {}

#[derive(Debug)]
pub enum KvGetError<InternalError> {
    NotFound(Vec<u8>),
    Internal(InternalError),
}

#[derive(Debug)]
pub enum KvInsertError<InternalError> {
    AlreadyExists(Vec<u8>, Vec<u8>),
    Internal(InternalError),
}

#[derive(Debug)]
pub enum KvDeleteError<InternalError> {
    NotFound(Vec<u8>),
    Internal(InternalError),
}
