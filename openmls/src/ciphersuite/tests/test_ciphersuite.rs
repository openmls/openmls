//! Unit tests for the ciphersuites.

use crate::ciphersuite::*;
use crate::config::Config;

// Spot test to make sure hpke seal/open work.
#[test]
fn test_hpke_seal_open() {
    // Test through ciphersuites.
    for ciphersuite in Config::supported_ciphersuites() {
        println!("Test {:?}", ciphersuite.name());
        println!("Ciphersuite {:?}", ciphersuite);
        let plaintext = &[1, 2, 3];
        let kp = ciphersuite.derive_hpke_keypair(&Secret::random(ciphersuite, None));
        let ciphertext = ciphersuite.hpke_seal(kp.public_key(), &[], &[], plaintext);
        let decrypted_payload = ciphersuite
            .hpke_open(&ciphertext, kp.private_key(), &[], &[])
            .expect("Unexpected error while decrypting a valid ciphertext.");
        assert_eq!(decrypted_payload, plaintext);

        let mut broken_kem_output = ciphertext.kem_output.clone();
        broken_kem_output.pop();
        let mut broken_ciphertext = ciphertext.ciphertext.clone();
        broken_ciphertext.pop();
        let broken_ciphertext1 = HpkeCiphertext {
            kem_output: broken_kem_output,
            ciphertext: ciphertext.ciphertext.clone(),
        };
        let broken_ciphertext2 = HpkeCiphertext {
            kem_output: ciphertext.kem_output.clone(),
            ciphertext: broken_ciphertext,
        };
        assert_eq!(
            ciphersuite
                .hpke_open(&broken_ciphertext1, kp.private_key(), &[], &[])
                .expect_err("Erroneously correct ciphertext decryption of broken ciphertext."),
            CryptoError::HpkeDecryptionError
        );
        assert_eq!(
            ciphersuite
                .hpke_open(&broken_ciphertext2, kp.private_key(), &[], &[])
                .expect_err("Erroneously correct ciphertext decryption of broken ciphertext."),
            CryptoError::HpkeDecryptionError
        );
    }
}

#[test]
fn test_sign_verify() {
    for ciphersuite in Config::supported_ciphersuites() {
        let keypair = ciphersuite.signature_scheme().new_keypair().unwrap();
        let payload = &[1, 2, 3];
        let signature = keypair.sign(payload).unwrap();
        assert!(keypair.verify(&signature, payload).is_ok());
    }
}

#[test]
fn supported_ciphersuites() {
    const SUPPORTED_CIPHERSUITE_NAMES: &[CiphersuiteName] = &[
        CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256,
    ];

    const UNSUPPORTED_CIPHERSUITE_NAMES: &[CiphersuiteName] = &[
        CiphersuiteName::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448,
        CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521,
        CiphersuiteName::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
    ];

    for ciphersuite_name in SUPPORTED_CIPHERSUITE_NAMES {
        // Instantiate ciphersuite
        let ciphersuite = Ciphersuite::new(*ciphersuite_name)
            .expect("Could not instantiate a Ciphersuite object.");
        // Create signature keypair
        let _signature_keypair = SignatureKeypair::new(ciphersuite.signature_scheme())
            .expect("Could not create signature keypair.");
    }

    for ciphersuite_name in UNSUPPORTED_CIPHERSUITE_NAMES {
        // Instantiate ciphersuite
        let _ciphersuite = Ciphersuite::new(*ciphersuite_name)
            .expect_err("Could instantiate a Ciphersuite object with an unsupported ciphersuite.");
        // Create signature keypair
        let _signature_keypair = SignatureKeypair::new(SignatureScheme::from(*ciphersuite_name))
            .expect_err("Could create signature keypair with unsupported ciphersuite.");
    }
}

#[test]
fn test_signatures() {
    for ciphersuite in Config::supported_ciphersuites() {
        // Test that valid signatures are properly verified.
        let payload = vec![0u8];
        let signature_scheme =
            SignatureScheme::try_from(ciphersuite.name()).expect("error deriving signature scheme");
        let keypair =
            SignatureKeypair::new(signature_scheme).expect("error generating signature keypair");
        let mut signature = keypair.sign(&payload).expect("error creating signature");
        println!("Done signing payload\n");
        keypair
            .verify(&signature, &payload)
            .expect("error verifying signature");
        println!("Done verifying payload\n");

        // Tamper with signature such that verification fails. We choose a byte
        // somewhere in the middle to make the verification fail, not the DER
        // decoding (in the case of ECDSA signatures).
        let mut modified_signature = signature.value.as_slice().to_vec();
        modified_signature[20] ^= 0xFF;
        signature.modify(&modified_signature);

        assert_eq!(
            keypair
                .verify(&signature, &payload)
                .expect_err("error verifying signature"),
            SignatureError::InvalidSignature
        );
    }
}

#[test]
fn test_der_encoding() {
    // Choosing a ciphersuite with an ECDSA signature scheme.
    let ciphersuite =
        Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256).unwrap();
    let payload = vec![0u8];
    let signature_scheme =
        SignatureScheme::try_from(ciphersuite.name()).expect("error deriving signature scheme");
    let keypair =
        SignatureKeypair::new(signature_scheme).expect("error generating signature keypair");
    let mut signature = keypair.sign(&payload).expect("error creating signature");

    // Make sure that signatures are DER encoded and can be decoded to valid signatures
    let decoded_signature = signature
        .der_decode()
        .expect("Error decoding valid signature.");

    verify(
        SignatureMode::P256,
        Some(
            DigestMode::try_from(SignatureScheme::ECDSA_SECP256R1_SHA256)
                .expect("Couldn't get digest mode of P256"),
        ),
        &keypair.public_key.value,
        &decoded_signature,
        &payload,
    )
    .expect("error while verifying der decoded signature");

    // Encoding a de-coded signature should yield the same string.
    let re_encoded_signature =
        Signature::der_encode(&decoded_signature).expect("error encoding valid signature");

    assert_eq!(re_encoded_signature, signature);

    // Make sure that the signature still verifies.
    keypair
        .verify(&signature, &payload)
        .expect("error verifying signature");

    // Now we tamper with the original signature to make the decoding fail in
    // various ways.

    let original_bytes = signature.value.as_slice().to_vec();

    // Wrong sequence tag
    let mut wrong_sequence_tag = original_bytes.clone();
    wrong_sequence_tag[0] ^= 0xFF;
    signature.modify(&wrong_sequence_tag);

    assert_eq!(
        signature
            .der_decode()
            .expect_err("invalid signature successfully decoded"),
        SignatureError::DecodingError
    );

    // Too long to be valid (bytes will be left over after reading the
    // signature.)
    let mut too_long = original_bytes.clone();
    too_long.extend_from_slice(&original_bytes);
    signature.modify(&too_long);

    assert_eq!(
        signature
            .der_decode()
            .expect_err("invalid signature successfully decoded"),
        SignatureError::DecodingError
    );

    // Inaccurate length
    let mut inaccurate_length = original_bytes.clone();
    inaccurate_length[1] = 0x9F;
    signature.modify(&inaccurate_length);

    assert_eq!(
        signature
            .der_decode()
            .expect_err("invalid signature successfully decoded"),
        SignatureError::DecodingError
    );

    // Wrong integer tag
    let mut wrong_integer_tag = original_bytes.clone();
    wrong_integer_tag[3] ^= 0xFF;
    signature.modify(&wrong_integer_tag);

    assert_eq!(
        signature
            .der_decode()
            .expect_err("invalid signature successfully decoded"),
        SignatureError::DecodingError
    );

    // Scalar too long overall
    let mut scalar_too_long = original_bytes.clone();
    scalar_too_long[4] = 0x9F;
    signature.modify(&scalar_too_long);

    assert_eq!(
        signature
            .der_decode()
            .expect_err("invalid signature successfully decoded"),
        SignatureError::DecodingError
    );
}
