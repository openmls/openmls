use crate::spec_types::conversion::unchecked::PrivateSpecType;
use openmls_traits::storage::{Platform, Storage, Stored};

pub trait IntoPrivate<KvStore: Platform, S: Storage<KvStore>, T: PrivateSpecType> {
    fn into_private(stored: S::Stored<T::Public>) -> T {
        T::from_public_unchecked(stored.get())
    }
}

impl<KvStore: Platform, S: Storage<KvStore>, T: PrivateSpecType> IntoPrivate<KvStore, S, T>
    for S::Stored<T::Public>
{
}
