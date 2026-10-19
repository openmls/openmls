//! ML-KEM + NIST curve hybrid KEMs (MLKEM768-P256, MLKEM1024-P384) in the
//! libcrux provider, and the `draft-ietf-mls-pq-ciphersuites` ciphersuites
//! built on them.
#![cfg(feature = "draft-ietf-mls-pq-ciphersuites")]

use openmls_libcrux_crypto::CryptoProvider as Libcrux;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{Ciphersuite, HpkeKemType},
};

/// One ciphersuite per hybrid KEM, with the expected public key length
/// (ML-KEM encapsulation key || uncompressed SEC1 point).
const KEMS: [(Ciphersuite, HpkeKemType, usize); 2] = [
    (
        Ciphersuite::MLS_128_MLKEM768P256_AES128GCM_SHA256_P256,
        HpkeKemType::MlKem768P256,
        1184 + 65,
    ),
    (
        Ciphersuite::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384,
        HpkeKemType::MlKem1024P384,
        1568 + 97,
    ),
];

#[test]
fn supported_ciphersuites() {
    let libcrux = Libcrux::new().unwrap();
    for cs in [
        Ciphersuite::MLS_128_MLKEM768P256_AES128GCM_SHA256_P256,
        Ciphersuite::MLS_128_MLKEM768P256_AES256GCM_SHA384_P256,
    ] {
        libcrux.supports(cs).unwrap();
        assert!(libcrux.supported_ciphersuites().contains(&cs), "{cs}");
    }

    // libcrux has no ECDSA P-384.
    for cs in [
        Ciphersuite::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384,
        Ciphersuite::MLS_192_MLKEM1024_AES256GCM_SHA384_P384,
    ] {
        assert!(libcrux.supports(cs).is_err(), "{cs}");
        assert!(!libcrux.supported_ciphersuites().contains(&cs), "{cs}");
    }
}

#[test]
fn derive_key_pair() {
    let libcrux = Libcrux::new().unwrap();
    for (cs, kem, pk_len) in KEMS {
        assert_eq!(cs.hpke_kem_algorithm(), kem);
        let ikm = [7u8; 32];
        let a = libcrux.derive_hpke_keypair(cs.hpke_config(), &ikm).unwrap();
        let b = libcrux.derive_hpke_keypair(cs.hpke_config(), &ikm).unwrap();
        assert_eq!(a.public, b.public, "{kem:?}: derivation is deterministic");
        assert_eq!(&*a.private, &*b.private);
        assert_eq!(a.public.len(), pk_len, "{kem:?}: public key length");

        let c = libcrux
            .derive_hpke_keypair(cs.hpke_config(), &[8u8; 32])
            .unwrap();
        assert_ne!(a.public, c.public, "{kem:?}: different ikm, different key");
    }
}

#[test]
fn seal_open() {
    let libcrux = Libcrux::new().unwrap();
    for (cs, kem, _) in KEMS {
        let kp = libcrux
            .derive_hpke_keypair(cs.hpke_config(), &[1u8; 32])
            .unwrap();
        let ct = libcrux
            .hpke_seal(cs.hpke_config(), &kp.public, b"info", b"aad", b"hello")
            .unwrap();
        let pt = libcrux
            .hpke_open(cs.hpke_config(), &ct, &kp.private, b"info", b"aad")
            .unwrap();
        assert_eq!(pt, b"hello", "{kem:?}");

        assert!(
            libcrux
                .hpke_open(cs.hpke_config(), &ct, &kp.private, b"info", b"aae")
                .is_err(),
            "{kem:?}: wrong aad must fail"
        );
        let other = libcrux
            .derive_hpke_keypair(cs.hpke_config(), &[2u8; 32])
            .unwrap();
        assert!(
            libcrux
                .hpke_open(cs.hpke_config(), &ct, &other.private, b"info", b"aad")
                .is_err(),
            "{kem:?}: wrong key must fail"
        );
    }
}

#[test]
fn export() {
    let libcrux = Libcrux::new().unwrap();
    for (cs, kem, _) in KEMS {
        let kp = libcrux
            .derive_hpke_keypair(cs.hpke_config(), &[3u8; 32])
            .unwrap();
        let (enc, sender) = libcrux
            .hpke_setup_sender_and_export(cs.hpke_config(), &kp.public, b"info", b"ctx", 32)
            .unwrap();
        let receiver = libcrux
            .hpke_setup_receiver_and_export(
                cs.hpke_config(),
                &enc,
                &kp.private,
                b"info",
                b"ctx",
                32,
            )
            .unwrap();
        assert_eq!(&*sender, &*receiver, "{kem:?}");
        assert_eq!(sender.len(), 32);
    }
}
