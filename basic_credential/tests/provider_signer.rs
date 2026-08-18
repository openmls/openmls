//! `SignatureKeyPair::generate` + `SignatureKeyPair::signer`: key generation
//! and signing go through the crypto provider, and the resulting keys and
//! signatures interoperate with the RustCrypto-based `Signer` impl.

use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{
    crypto::OpenMlsCrypto, signatures::Signer, types::SignatureScheme, OpenMlsProvider,
};

fn schemes(crypto: &impl OpenMlsCrypto) -> Vec<SignatureScheme> {
    // Every scheme some supported ciphersuite uses.
    let mut schemes: Vec<_> = crypto
        .supported_ciphersuites()
        .into_iter()
        .map(|cs| cs.signature_algorithm())
        .collect();
    schemes.sort_by_key(|s| *s as u16);
    schemes.dedup();
    schemes
}

fn check(crypto: &impl OpenMlsCrypto) {
    let payload = b"payload";
    for scheme in schemes(crypto) {
        // Provider-generated key, provider signer, provider verify.
        let key_pair = SignatureKeyPair::generate(crypto, scheme).unwrap();
        let signer = key_pair.signer(crypto);
        assert_eq!(signer.signature_scheme(), scheme);
        let signature = signer.sign(payload).unwrap();
        crypto
            .verify_signature(scheme, payload, key_pair.public(), &signature)
            .unwrap_or_else(|e| panic!("{scheme:?}: provider rejected provider signature: {e:?}"));
        assert!(crypto
            .verify_signature(scheme, b"other", key_pair.public(), &signature)
            .is_err());

        // Provider-generated key is drop-in for the RustCrypto `Signer` impl.
        let signature = key_pair.sign(payload).unwrap();
        crypto
            .verify_signature(scheme, payload, key_pair.public(), &signature)
            .unwrap_or_else(|e| {
                panic!("{scheme:?}: provider rejected RustCrypto signature: {e:?}")
            });

        // RustCrypto-generated key is drop-in for the provider signer.
        let key_pair = SignatureKeyPair::new(scheme).unwrap();
        let signature = key_pair.signer(crypto).sign(payload).unwrap();
        crypto
            .verify_signature(scheme, payload, key_pair.public(), &signature)
            .unwrap_or_else(|e| {
                panic!("{scheme:?}: provider rejected signature with RustCrypto key: {e:?}")
            });
    }
}

#[test]
fn rust_crypto() {
    check(openmls_rust_crypto::OpenMlsRustCrypto::default().crypto());
}

#[test]
fn libcrux() {
    check(openmls_libcrux_crypto::Provider::default().crypto());
}

#[test]
fn unsupported_scheme_is_an_error() {
    let provider = openmls_libcrux_crypto::Provider::default();
    // The libcrux provider has no P-521 support.
    assert!(
        SignatureKeyPair::generate(provider.crypto(), SignatureScheme::ECDSA_SECP521R1_SHA512)
            .is_err()
    );
}
