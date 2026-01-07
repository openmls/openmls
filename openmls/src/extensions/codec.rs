use std::io::{Read, Write};

use tls_codec::{Deserialize, DeserializeBytes, Serialize, Size, VLBytes};

use crate::extensions::{
    ApplicationIdExtension, Extension, ExtensionType, ExternalPubExtension,
    ExternalSendersExtension, RatchetTreeExtension, RequiredCapabilitiesExtension,
    UnknownExtension,
};

use super::last_resort::LastResortExtension;

fn vlbytes_len_len(length: usize) -> usize {
    if length < 0x40 {
        1
    } else if length < 0x3fff {
        2
    } else if length < 0x3fff_ffff {
        4
    } else {
        8
    }
}

impl Size for Extension {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        let extension_type_length = 2;

        // We truncate here and don't catch errors for anything that's
        // too long.
        // This will be caught when (de)serializing.
        let extension_data_len = match self {
            Extension::ApplicationId(e) => e.tls_serialized_len(),
            Extension::RatchetTree(e) => e.tls_serialized_len(),
            Extension::RequiredCapabilities(e) => e.tls_serialized_len(),
            Extension::ExternalPub(e) => e.tls_serialized_len(),
            Extension::ExternalSenders(e) => e.tls_serialized_len(),
            Extension::LastResort(e) => e.tls_serialized_len(),
            Extension::Unknown(_, e) => e.0.len(),
        };

        let vlbytes_len_len = vlbytes_len_len(extension_data_len);

        extension_type_length + vlbytes_len_len + extension_data_len
    }
}

impl Size for &Extension {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        Extension::tls_serialized_len(*self)
    }
}

impl Serialize for Extension {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        // First write the extension type.
        let written = self.extension_type().tls_serialize(writer)?;

        // Now serialize the extension into a separate byte vector.
        let extension_data_len = self.tls_serialized_len();
        let mut extension_data = Vec::with_capacity(extension_data_len);

        let extension_data_written = match self {
            Extension::ApplicationId(e) => e.tls_serialize(&mut extension_data),
            Extension::RatchetTree(e) => e.tls_serialize(&mut extension_data),
            Extension::RequiredCapabilities(e) => e.tls_serialize(&mut extension_data),
            Extension::ExternalPub(e) => e.tls_serialize(&mut extension_data),
            Extension::ExternalSenders(e) => e.tls_serialize(&mut extension_data),
            Extension::LastResort(e) => e.tls_serialize(&mut extension_data),
            Extension::Unknown(_, e) => extension_data
                .write_all(e.0.as_slice())
                .map(|_| e.0.len())
                .map_err(|_| tls_codec::Error::EndOfStream),
        }?;
        debug_assert_eq!(
            extension_data_written,
            extension_data_len - 2 - vlbytes_len_len(extension_data_written)
        );
        debug_assert_eq!(extension_data_written, extension_data.len());

        // Write the serialized extension out.
        extension_data.tls_serialize(writer).map(|l| l + written)
    }
}

impl Serialize for &Extension {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Extension::tls_serialize(*self, writer)
    }
}

impl Deserialize for Extension {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        // Read the extension type and extension data.
        let extension_type = ExtensionType::tls_deserialize(bytes)?;
        let extension_data = VLBytes::tls_deserialize(bytes)?;

        // Now deserialize the extension itself from the extension data.
        let mut extension_data = extension_data.as_slice();
        Ok(match extension_type {
            ExtensionType::ApplicationId => Extension::ApplicationId(
                ApplicationIdExtension::tls_deserialize(&mut extension_data)?,
            ),
            ExtensionType::RatchetTree => {
                Extension::RatchetTree(RatchetTreeExtension::tls_deserialize(&mut extension_data)?)
            }
            ExtensionType::RequiredCapabilities => Extension::RequiredCapabilities(
                RequiredCapabilitiesExtension::tls_deserialize(&mut extension_data)?,
            ),
            ExtensionType::ExternalPub => {
                Extension::ExternalPub(ExternalPubExtension::tls_deserialize(&mut extension_data)?)
            }
            ExtensionType::ExternalSenders => Extension::ExternalSenders(
                ExternalSendersExtension::tls_deserialize(&mut extension_data)?,
            ),
            ExtensionType::LastResort => {
                Extension::LastResort(LastResortExtension::tls_deserialize(&mut extension_data)?)
            }
            ExtensionType::Grease(grease) | ExtensionType::Unknown(grease) => {
                Extension::Unknown(grease, UnknownExtension(extension_data.to_vec()))
            }
        })
    }
}

impl DeserializeBytes for Extension {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), tls_codec::Error>
    where
        Self: Sized,
    {
        let mut bytes_ref = bytes;
        let extension = Extension::tls_deserialize(&mut bytes_ref)?;
        let remainder = &bytes[extension.tls_serialized_len()..];
        Ok((extension, remainder))
    }
}
