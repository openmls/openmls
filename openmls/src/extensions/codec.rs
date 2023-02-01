use std::io::{Read, Write};

use tls_codec::{Deserialize, Serialize, Size, VLBytes};

use crate::extensions::{
    ApplicationIdExtension, Extension, ExtensionType, ExternalPubExtension,
    ExternalSendersExtension, RatchetTreeExtension, RequiredCapabilitiesExtension,
};

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
        2 + /* extension type len */
        match self {
                // We truncate here and don't catch errors for anything that's
                // too long.
                // This will be caught when (de)serializing.
                Extension::ApplicationId(e) => {
                    let len = e.tls_serialized_len();
                    len + vlbytes_len_len(len)
                },
                Extension::RatchetTree(e) => {
                    let len = e.tls_serialized_len();
                    len + vlbytes_len_len(len)
                },
                Extension::RequiredCapabilities(e) => {
                    let len = e.tls_serialized_len();
                    len + vlbytes_len_len(len)
                },
                Extension::ExternalPub(e) => {
                    let len = e.tls_serialized_len();
                    len + vlbytes_len_len(len)
                },
                Extension::ExternalSenders(e) => {
                    let len = e.tls_serialized_len();
                    len + vlbytes_len_len(len)
                },
            }
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
        })
    }
}
