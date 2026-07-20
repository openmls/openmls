use super::*;

/// `KdfLabel` is later serialized and used in the `label` field of
/// `kdf_expand_label`.
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// struct {
///     uint16 length = Length;
///     opaque label<V> = "MLS 1.0 " + Label;
///     opaque context<V> = Context;
/// } KDFLabel;
/// ```
#[derive(Debug, TlsSerialize, TlsSize)]
pub(in crate::ciphersuite) struct KdfLabel {
    length: u16,
    label: VLBytes,
    context: VLBytes,
}
