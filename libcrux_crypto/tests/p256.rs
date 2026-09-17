//! ECDSA P-256 in the libcrux provider: round-trip within libcrux and
//! cross-provider with RustCrypto (raw-scalar private key, uncompressed SEC1
//! public key, DER signatures).

use openmls_libcrux_crypto::CryptoProvider as Libcrux;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, types::SignatureScheme};

const SCHEME: SignatureScheme = SignatureScheme::ECDSA_SECP256R1_SHA256;

#[test]
fn round_trip() {
    let libcrux = Libcrux::new().unwrap();
    let (sk, pk) = libcrux.signature_key_gen(SCHEME).unwrap();
    assert_eq!(sk.len(), 32, "private key is the raw scalar");
    assert_eq!(pk.len(), 65, "public key is an uncompressed SEC1 point");
    assert_eq!(pk[0], 0x04);

    let sig = libcrux.sign(SCHEME, b"hello", &sk).unwrap();
    libcrux
        .verify_signature(SCHEME, b"hello", &pk, &sig)
        .unwrap();
    assert!(libcrux
        .verify_signature(SCHEME, b"hellp", &pk, &sig)
        .is_err());
}

#[test]
fn cross_provider() {
    let libcrux = Libcrux::new().unwrap();
    let rust_crypto = RustCrypto::default();

    let (sk_l, pk_l) = libcrux.signature_key_gen(SCHEME).unwrap();
    let (sk_r, pk_r) = rust_crypto.signature_key_gen(SCHEME).unwrap();
    assert_eq!(pk_l.len(), pk_r.len(), "public key size");

    // Both key origins, both signing directions. Since ECDSA signatures are
    // randomized, repeat a few times to exercise different DER lengths
    // (leading-zero stripping, high-bit padding).
    for _ in 0..16 {
        for (sk, pk) in [(&sk_l, &pk_l), (&sk_r, &pk_r)] {
            let sig = libcrux.sign(SCHEME, b"msg", sk).unwrap();
            rust_crypto
                .verify_signature(SCHEME, b"msg", pk, &sig)
                .expect("RustCrypto rejected libcrux DER signature");

            let sig = rust_crypto.sign(SCHEME, b"msg", sk).unwrap();
            libcrux
                .verify_signature(SCHEME, b"msg", pk, &sig)
                .expect("libcrux rejected RustCrypto DER signature");
        }
    }
}
