use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use super::{Deserialize, Serialize};
use crate::ciphersuite::HpkePublicKey;

/// ```c
/// // draft-ietf-mls-protocol-16
/// struct {
///     HPKEPublicKey external_pub;
/// } ExternalPub;
/// ```
#[derive(
    PartialEq, Eq, Clone, Debug, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct ExternalPubExtension {
    external_pub: HpkePublicKey,
}

impl ExternalPubExtension {
    /// Create a new `external_pub` extension.
    pub fn new(external_pub: HpkePublicKey) -> Self {
        Self { external_pub }
    }

    /// Get a reference to the HPKE public key.
    pub fn external_pub(&self) -> &HpkePublicKey {
        &self.external_pub
    }
}

#[cfg(test)]
mod test {
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite, OpenMlsProvider};
    use tls_codec::{Deserialize, Serialize};

    use super::*;
    use crate::{prelude_test::Secret, versions::ProtocolVersion};

    #[test]
    fn test_serialize_deserialize() {
        let tests = {
            let provider = OpenMlsRustCrypto::default();

            let mut external_pub_extensions = Vec::new();

            for _ in 0..8 {
                let hpke_public_key = {
                    let ikm = Secret::random(
                        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                        provider.rand(),
                        ProtocolVersion::default(),
                    )
                    .unwrap();
                    let init_key = provider.crypto().derive_hpke_keypair(
                        Ciphersuite::hpke_config(
                            &Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                        ),
                        ikm.as_slice(),
                    );
                    init_key.public
                };

                external_pub_extensions.push(ExternalPubExtension::new(hpke_public_key.into()));
            }

            external_pub_extensions
        };

        for expected in tests {
            let serialized = expected.tls_serialize_detached().unwrap();
            let got = ExternalPubExtension::tls_deserialize_exact(serialized).unwrap();
            assert_eq!(expected, got);
        }
    }
}
