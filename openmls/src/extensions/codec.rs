use std::io::{Read, Write};

use tls_codec::{Deserialize, Serialize, Size, TlsByteVecU32, TlsSliceU32};

use crate::extensions::{
    ApplicationIdExtension, CapabilitiesExtension, Extension, ExtensionType, LifetimeExtension,
    ParentHashExtension, RatchetTreeExtension, RequiredCapabilitiesExtension,
};

impl Size for Extension {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        2 /* extension type len */
            + 4 /* u32 len */ +
            match self {
                Extension::Capabilities(e) => e.tls_serialized_len(),
                Extension::ApplicationId(e) => e.tls_serialized_len(),
                Extension::Lifetime(e) => e.tls_serialized_len(),
                Extension::ParentHash(e) => e.tls_serialized_len(),
                Extension::RatchetTree(e) => e.tls_serialized_len(),
                Extension::RequiredCapabilities(e) => e.tls_serialized_len(),
            }
    }
}

impl Serialize for Extension {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        // First write the extension type.
        let written = self.extension_type().tls_serialize(writer)?;

        // Now serialize the extension into a separate byte vector.
        let extension_data_len = self.tls_serialized_len() - 6 /* extension type length and u32 length */;
        let mut extension_data = Vec::with_capacity(extension_data_len);

        let extension_data_written = match self {
            Extension::Capabilities(e) => e.tls_serialize(&mut extension_data),
            Extension::ApplicationId(e) => e.tls_serialize(&mut extension_data),
            Extension::Lifetime(e) => e.tls_serialize(&mut extension_data),
            Extension::ParentHash(e) => e.tls_serialize(&mut extension_data),
            Extension::RatchetTree(e) => e.tls_serialize(&mut extension_data),
            Extension::RequiredCapabilities(e) => e.tls_serialize(&mut extension_data),
        }?;
        debug_assert_eq!(extension_data_written, extension_data_len);
        debug_assert_eq!(extension_data_written, extension_data.len());

        // Write the serialized extension out.
        TlsSliceU32(&extension_data)
            .tls_serialize(writer)
            .map(|l| l + written)
    }
}

impl Deserialize for Extension {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        // Read the extension type and extension data.
        let extension_type = ExtensionType::tls_deserialize(bytes)?;
        let extension_data = TlsByteVecU32::tls_deserialize(bytes)?;

        // Now deserialize the extension itself from the extension data.
        let mut extension_data = extension_data.as_slice();
        Ok(match extension_type {
            ExtensionType::Capabilities => Extension::Capabilities(
                CapabilitiesExtension::tls_deserialize(&mut extension_data)?,
            ),
            ExtensionType::ApplicationId => Extension::ApplicationId(
                ApplicationIdExtension::tls_deserialize(&mut extension_data)?,
            ),
            ExtensionType::Lifetime => {
                Extension::Lifetime(LifetimeExtension::tls_deserialize(&mut extension_data)?)
            }
            ExtensionType::ParentHash => {
                Extension::ParentHash(ParentHashExtension::tls_deserialize(&mut extension_data)?)
            }
            ExtensionType::RatchetTree => {
                Extension::RatchetTree(RatchetTreeExtension::tls_deserialize(&mut extension_data)?)
            }
            ExtensionType::RequiredCapabilities => Extension::RequiredCapabilities(
                RequiredCapabilitiesExtension::tls_deserialize(&mut extension_data)?,
            ),
            ExtensionType::Reserved => {
                return Err(tls_codec::Error::DecodingError(format!(
                    "{:?} is not a valid extension type",
                    extension_type
                )))
            }
        })
    }
}
