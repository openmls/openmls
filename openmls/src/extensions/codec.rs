use std::io::{Read, Write};

use tls_codec::{Deserialize, DeserializeBytes, Serialize, Size, VLBytes};

use crate::extensions::{Extension, ExtensionType, UnknownExtension};

/// Known extension types must consume the bounded payload without silently dropping trailing bytes.
fn deserialize_extension_exact<T: Deserialize>(
    extension_data: &[u8],
) -> Result<T, tls_codec::Error> {
    T::tls_deserialize_exact(extension_data)
}

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
            #[cfg(feature = "extensions-draft")]
            Extension::AppDataDictionary(e) => e.tls_serialized_len(),
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
            #[cfg(feature = "extensions-draft")]
            Extension::AppDataDictionary(e) => e.tls_serialize(&mut extension_data),
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
        let extension_data = extension_data.as_slice();
        Ok(match extension_type {
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
            #[cfg(feature = "extensions-draft")]
            ExtensionType::AppDataDictionary => {
                Extension::AppDataDictionary(deserialize_extension_exact(extension_data)?)
            }
            ExtensionType::LastResort => {
                Extension::LastResort(deserialize_extension_exact(extension_data)?)
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

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "extensions-draft")]
    use crate::extensions::AppDataDictionaryExtension;
    use crate::{
        credentials::CredentialType,
        extensions::{
            ApplicationIdExtension, ExternalPubExtension, ExternalSendersExtension,
            LastResortExtension, RequiredCapabilitiesExtension,
        },
        messages::proposals::ProposalType,
        treesync::RatchetTreeIn,
    };

    fn serialize_extension(extension_type: ExtensionType, payload: Vec<u8>) -> Vec<u8> {
        let mut serialized = extension_type.tls_serialize_detached().unwrap();
        serialized.extend(VLBytes::from(payload).tls_serialize_detached().unwrap());
        serialized
    }

    fn known_extensions() -> Vec<(ExtensionType, Vec<u8>)> {
        let extensions = vec![
            (
                ExtensionType::ApplicationId,
                ApplicationIdExtension::new(&[1, 2, 3])
                    .tls_serialize_detached()
                    .unwrap(),
            ),
            (
                ExtensionType::RatchetTree,
                RatchetTreeIn::from_nodes(vec![])
                    .tls_serialize_detached()
                    .unwrap(),
            ),
            (
                ExtensionType::RequiredCapabilities,
                RequiredCapabilitiesExtension::new(
                    &[ExtensionType::ApplicationId],
                    &[ProposalType::Add],
                    &[CredentialType::Basic],
                )
                .tls_serialize_detached()
                .unwrap(),
            ),
            (
                ExtensionType::ExternalPub,
                ExternalPubExtension::new(vec![4, 5, 6].into())
                    .tls_serialize_detached()
                    .unwrap(),
            ),
            (
                ExtensionType::ExternalSenders,
                ExternalSendersExtension::new()
                    .tls_serialize_detached()
                    .unwrap(),
            ),
            (
                ExtensionType::LastResort,
                LastResortExtension::new().tls_serialize_detached().unwrap(),
            ),
        ];

        #[cfg(feature = "extensions-draft")]
        let extensions = {
            let mut extensions = extensions;
            extensions.push((
                ExtensionType::AppDataDictionary,
                AppDataDictionaryExtension::default()
                    .tls_serialize_detached()
                    .unwrap(),
            ));
            extensions
        };

        extensions
    }

    #[test]
    fn known_extensions_round_trip() {
        for (extension_type, payload) in known_extensions() {
            let serialized = serialize_extension(extension_type, payload);
            let extension = Extension::tls_deserialize_exact(&serialized).unwrap();
            assert_eq!(extension.tls_serialize_detached().unwrap(), serialized);
        }
    }

    #[test]
    fn known_extensions_reject_trailing_payload_bytes() {
        for (extension_type, mut payload) in known_extensions() {
            payload.extend([0xa5, 0x5a]);
            let serialized = serialize_extension(extension_type, payload);
            assert_eq!(
                Extension::tls_deserialize_exact(&serialized).unwrap_err(),
                tls_codec::Error::TrailingData
            );
        }
    }

    #[cfg(feature = "extensions-draft")]
    #[test]
    fn app_data_dictionary_uses_exact_payload_decoding() {
        use crate::extensions::AppDataDictionary;

        let mut dictionary = AppDataDictionary::new();
        dictionary.insert(0x8001, vec![1, 2, 3]);
        let mut payload = AppDataDictionaryExtension::new(dictionary)
            .tls_serialize_detached()
            .unwrap();
        payload.push(0xff);

        let serialized = serialize_extension(ExtensionType::AppDataDictionary, payload);
        assert_eq!(
            Extension::tls_deserialize_exact(serialized).unwrap_err(),
            tls_codec::Error::TrailingData
        );
    }

    #[test]
    fn opaque_extensions_round_trip_arbitrary_payload() {
        let payload = vec![0x00, 0xff, 0x01, 0xfe, 0x80];
        for extension_type in [
            ExtensionType::Unknown(0xf042),
            ExtensionType::Grease(0x0a0a),
        ] {
            let serialized = serialize_extension(extension_type, payload.clone());
            let extension = Extension::tls_deserialize_exact(&serialized).unwrap();
            assert_eq!(
                extension,
                Extension::Unknown(u16::from(extension_type), UnknownExtension(payload.clone()))
            );
            assert_eq!(extension.tls_serialize_detached().unwrap(), serialized);
        }
    }
}
