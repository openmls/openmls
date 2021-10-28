use super::*;

/// `KdfLabel` is later serialized and used in the `label` field of
/// `kdf_expand_label`.
#[derive(TlsSerialize, TlsSize)]
pub(in crate::ciphersuite) struct KdfLabel {
    length: u16,
    label: TlsByteVecU8,
    context: TlsByteVecU32,
}

impl KdfLabel {
    /// Serialize this label.
    /// Returns the serialized label as byte vector or returns a [`CryptoError`]
    /// if the parameters are invalid.
    pub(in crate::ciphersuite) fn serialized_label(
        context: &[u8],
        label: String,
        length: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        if length > u16::MAX.into() {
            debug_assert!(
                false,
                "Library error: Trying to derive a key with a too large length field!"
            );
            return Err(CryptoError::KdfLabelTooLarge);
        }
        log::trace!(
            "KDF Label:\n length: {:?}\n label: {:?}\n context: {:x?}",
            length as u16,
            label,
            context
        );
        let kdf_label = KdfLabel {
            length: length as u16,
            label: label.as_bytes().into(),
            context: context.into(),
        };
        kdf_label
            .tls_serialize_detached()
            .map_err(|_| CryptoError::KdfSerializationError)
    }
}
