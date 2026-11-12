use openmls_libcrux_crypto::CryptoProvider;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{CryptoError, SignatureScheme},
};

#[test]
fn provider_rejects_small_order_key_forgery_and_accepts_valid_signatures() {
    let provider = CryptoProvider::new().expect("OS randomness must be available");
    let (private_key, public_key) = provider
        .signature_key_gen(SignatureScheme::ED25519)
        .expect("the provider supports Ed25519 key generation");
    let message = b"valid libcrux signature";
    let signature = provider
        .sign(SignatureScheme::ED25519, message, &private_key)
        .expect("the provider supports Ed25519 signing");
    provider
        .verify_signature(SignatureScheme::ED25519, message, &public_key, &signature)
        .expect("a valid libcrux signature must verify");

    let mut identity = [0; 32];
    identity[0] = 1;
    let mut forgery = [0; 64];
    forgery[..32].copy_from_slice(&identity);

    for message in [b"first message".as_slice(), b"second message".as_slice()] {
        assert!(
            matches!(
                provider.verify_signature(SignatureScheme::ED25519, message, &identity, &forgery),
                Err(CryptoError::InvalidSignature)
            ),
            "the identity key and R point must not verify arbitrary messages"
        );
    }
}
