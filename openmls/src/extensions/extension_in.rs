use std::{collections::hash_set::HashSet, io::Read, marker::PhantomData};

use tls_codec::{Deserialize, Size, VLBytes};

use crate::{
    extensions::{
        codec::deserialize_extension_exact, Extension, ExtensionType, Extensions,
        InvalidExtensionError, UnknownExtension,
    },
    prelude::ExtensionValidator,
};

/// An [`Extension`] decoded in the context of `T`, i.e. its extension type
/// was checked with `T::validate_extension_type` during deserialization.
/// Only used as an intermediate when deserializing [`Extensions<T>`].
///
/// [`Extensions<T>`]: crate::extensions::Extensions
#[repr(transparent)]
pub struct ExtensionIn<T>(Extension, PhantomData<T>);

impl<T: ExtensionValidator> ExtensionIn<T> {
    pub fn into_extension(self) -> Extension {
        self.0
    }

    pub fn extension_type(&self) -> ExtensionType {
        self.0.extension_type()
    }
}

impl<T: ExtensionValidator> TryFrom<Vec<ExtensionIn<T>>> for Extensions<T>
where
    InvalidExtensionError: From<T::Error>,
{
    type Error = InvalidExtensionError;

    fn try_from(candidate: Vec<ExtensionIn<T>>) -> Result<Self, Self::Error> {
        let mut seen = HashSet::with_capacity(candidate.len());
        for extension in candidate.iter() {
            if !seen.insert(extension.extension_type()) {
                return Err(InvalidExtensionError::Duplicate);
            }
        }

        Ok(Self {
            unique: candidate
                .into_iter()
                .map(ExtensionIn::into_extension)
                .collect(),
            _object: PhantomData,
        })
    }
}

impl<T: ExtensionValidator> Size for ExtensionIn<T> {
    fn tls_serialized_len(&self) -> usize {
        self.0.tls_serialized_len()
    }
}

impl<T: ExtensionValidator> Deserialize for ExtensionIn<T> {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        // Read the extension type and extension data.
        let extension_type = ExtensionType::tls_deserialize(bytes)?;
        let extension_data = VLBytes::tls_deserialize(bytes)?;

        // Ensure the extension type is valid in this context
        #[allow(deprecated)]
        T::really_validate_extension_type(extension_type)
            .map_err(T::error_to_string)
            .map_err(|e| tls_codec::Error::DecodingError(e))?;

        // Now deserialize the extension itself from the extension data.
        let extension_data = extension_data.as_slice();
        let extension = match extension_type {
            ExtensionType::ApplicationId => {
                Extension::ApplicationId(deserialize_extension_exact(extension_data)?)
            }
            ExtensionType::RatchetTree => {
                Extension::RatchetTree(deserialize_extension_exact(extension_data)?)
            }
            ExtensionType::RequiredCapabilities => {
                Extension::RequiredCapabilities(deserialize_extension_exact(extension_data)?)
            }
            ExtensionType::ExternalPub => {
                Extension::ExternalPub(deserialize_extension_exact(extension_data)?)
            }
            ExtensionType::ExternalSenders => {
                Extension::ExternalSenders(deserialize_extension_exact(extension_data)?)
            }
            #[cfg(feature = "extensions-draft-08")]
            ExtensionType::AppDataDictionary => {
                Extension::AppDataDictionary(deserialize_extension_exact(extension_data)?)
            }
            ExtensionType::LastResort => {
                Extension::LastResort(deserialize_extension_exact(extension_data)?)
            }
            ExtensionType::Grease(grease) | ExtensionType::Unknown(grease) => {
                Extension::Unknown(grease, UnknownExtension(extension_data.to_vec()))
            }
        };

        Ok(Self(extension, PhantomData))
    }
}
