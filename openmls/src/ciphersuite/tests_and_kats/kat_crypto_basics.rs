//! # Known Answer Tests for basic crypto operations
//!
//! This test file generates and read test vectors for tree math.
//! See <https://github.com/mlswg/mls-implementations/blob/master/test-vectors.md>
//! for more description on the test vectors.
//!
//! Parameters:
//! * Ciphersuite
//!
//! Format:
//!
//! ```text
//! {
//!   "cipher_suite": /* uint16 */,
//!   "ref_hash": {
//!     "label": /* string */,
//!     "value": /* hex-encoded binary data */,
//!     "out": /* hex-encoded binary data */,
//!   }
//!   "expand_with_label": {
//!     "secret": /* hex-encoded binary data */,
//!     "label": /* string */,
//!     "context": /* hex-encoded binary data */,
//!     "length": /* uint16 */,
//!     "out": /* hex-encoded binary data */,
//!   },
//!   "derive_secret": {
//!     "secret": /* hex-encoded binary data */,
//!     "label": /* string */,
//!     "out": /* hex-encoded binary data */,
//!   },
//!   "derive_tree_secret": {
//!     "secret": /* hex-encoded binary data */,
//!     "label": /* string */
//!     "generation": /* uint32 */
//!     "length": /* uint16 */
//!     "out": /* hex-encoded binary data */,
//!   },
//!   "sign_with_label": {
//!     "priv": /* hex-encoded binary data */,
//!     "pub": /* hex-encoded binary data */,
//!     "content": /* hex-encoded binary data */,
//!     "label": /* string */,
//!     "signature": /* string */,
//!   },
//!   "encrypt_with_label": {
//!     "priv": /* hex-encoded binary data */,
//!     "pub": /* hex-encoded binary data */,
//!     "label": /* hex-encoded binary data */,
//!     "context": /* hex-encoded binary data */,
//!     "plaintext": /* hex-encoded binary data */,
//!     "kem_output": /* hex-encoded binary data */,
//!     "ciphertext": /* hex-encoded binary data */,
//!   }
//! }
//! ```
//!
//! Verification:
//!
//! * `ref_hash`: `out == RefHash(label, value)`
//! * `expand_with_label`: `out == ExpandWithLabel(secret, label, context, length)`
//! * `derive_secret`: `out == DeriveSecret(secret, label)`
//! * `derive_tree_secret`: `out == DeriveTreeSecret(secret, label, generation, length)`
//! * `sign_with_label`:
//!   * `VerifyWithLabel(pub, label, content, signature) == true`
//!   * `VerifyWithLabel(pub, label, content, SignWithLabel(priv, label, content)) == true`
//! * `encrypt_with_label`:
//!   * `DecryptWithLabel(priv, label, context, kem_output, ciphertext) == plaintext`
//!   * `kem_output_candidate, ciphertext_candidate = EncryptWithLabel(pub, label, context, plaintext)`
//!   * `DecryptWithLabel(priv, label, context, kem_output_candidate, ciphertext_candidate) == plaintext`

use crate::prelude_test::{
    signable::{Signable, SignedStruct, VerifiedStruct},
    Signature, Verifiable,
};
#[cfg(test)]
use crate::test_utils::*;

use openmls_basic_credential::SignatureKeyPair;
use serde::{self, Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RefHash {
    label: String,
    value: String,
    out: String,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExpandWithLabel {
    secret: String,
    label: String,
    context: String,
    length: u16,
    out: String,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeriveSecret {
    secret: String,
    label: String,
    out: String,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeriveTreeSecret {
    secret: String,
    label: String,
    generation: u32,
    length: u16,
    out: String,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignWithLabel {
    r#priv: String,
    r#pub: String,
    content: String,
    label: String,
    signature: String,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptWithLabel {
    r#priv: String,
    r#pub: String,
    label: String,
    context: String,
    plaintext: String,
    kem_output: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ParsedSignWithLabel {
    key: SignatureKeyPair,
    content: Vec<u8>,
    label: String,
    signature: Signature,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
struct SignWithLabelTest {
    key: SignatureKeyPair,
    content: Vec<u8>,
    label: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct MySignature(Signature);
impl SignedStruct<ParsedSignWithLabel> for MySignature {
    fn from_payload(_: ParsedSignWithLabel, signature: Signature) -> Self {
        Self(signature)
    }
}
impl SignedStruct<SignWithLabelTest> for MySignature {
    fn from_payload(_: SignWithLabelTest, signature: Signature) -> Self {
        Self(signature)
    }
}

impl Verifiable for ParsedSignWithLabel {
    type VerifiedStruct = ();

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        Ok(self.content.clone())
    }

    fn signature(&self) -> &crate::prelude_test::Signature {
        &self.signature
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn verify(
        self,
        crypto: &impl openmls_traits::crypto::OpenMlsCrypto,
        pk: &crate::ciphersuite::OpenMlsSignaturePublicKey,
    ) -> Result<Self::VerifiedStruct, crate::ciphersuite::signable::SignatureError> {
        self.verify_no_out(crypto, pk)?;
        Ok(())
    }
}

// Dummy implementation
impl VerifiedStruct for () {}

impl Signable for ParsedSignWithLabel {
    type SignedOutput = MySignature;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        Ok(self.content.clone())
    }

    fn label(&self) -> &str {
        &self.label
    }
}

impl Signable for SignWithLabelTest {
    type SignedOutput = MySignature;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        Ok(self.content.clone())
    }

    fn label(&self) -> &str {
        &self.label
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CryptoBasicsTestCase {
    cipher_suite: u16,
    ref_hash: RefHash,
    expand_with_label: ExpandWithLabel,
    derive_secret: DeriveSecret,
    derive_tree_secret: DeriveTreeSecret,
    sign_with_label: SignWithLabel,
    encrypt_with_label: EncryptWithLabel,
}

#[cfg(any(feature = "test-utils", test))]
pub fn run_test_vector(
    test: CryptoBasicsTestCase,
    provider: &OpenMlsRustCrypto,
) -> Result<(), String> {
    use openmls_traits::{crypto::OpenMlsCrypto, types::HpkeCiphertext};

    use crate::{
        prelude_test::{hash_ref, hpke, OpenMlsSignaturePublicKey, Secret},
        tree::secret_tree::derive_tree_secret,
    };

    let ciphersuite = Ciphersuite::try_from(test.cipher_suite).unwrap();
    // Skip unsupported ciphersuites.
    if !provider
        .crypto()
        .supported_ciphersuites()
        .contains(&ciphersuite)
    {
        log::debug!("Unsupported ciphersuite {ciphersuite:?} ...");
        return Ok(());
    }
    log::debug!("Basic crypto test for {ciphersuite:?} ...");

    //ref_hash
    {
        let label = test.ref_hash.label;
        let value = hex_to_bytes(&test.ref_hash.value);
        let out =
            hash_ref::HashReference::new(&value, ciphersuite, provider.crypto(), label.as_bytes())
                .unwrap();

        assert_eq!(&hex_to_bytes(&test.ref_hash.out), out.as_slice());
    }

    // expand_with_label
    {
        let secret = hex_to_bytes(&test.expand_with_label.secret);
        let label = test.expand_with_label.label;
        let context = hex_to_bytes(&test.expand_with_label.context);
        let length = test.expand_with_label.length;
        let out = Secret::from_slice(&secret)
            .kdf_expand_label(
                provider.crypto(),
                ciphersuite,
                &label,
                &context,
                length.into(),
            )
            .unwrap();

        assert_eq!(&hex_to_bytes(&test.expand_with_label.out), out.as_slice());
    }

    // derive_secret
    {
        let label = test.derive_secret.label;
        let secret = hex_to_bytes(&test.derive_secret.secret);
        let out = Secret::from_slice(&secret)
            .derive_secret(provider.crypto(), ciphersuite, &label)
            .unwrap();

        assert_eq!(&hex_to_bytes(&test.derive_secret.out), out.as_slice());
    }

    // sign with label
    {
        let private = hex_to_bytes(&test.sign_with_label.r#priv);
        let public = hex_to_bytes(&test.sign_with_label.r#pub);
        let label = test.sign_with_label.label;
        let content = hex_to_bytes(&test.sign_with_label.content);
        let signature = hex_to_bytes(&test.sign_with_label.signature).into();

        let mut parsed = ParsedSignWithLabel {
            key: SignatureKeyPair::from_raw(
                ciphersuite.signature_algorithm(),
                private,
                public.clone(),
            ),
            content,
            label,
            signature,
        };

        // sign
        let my_signature = parsed.clone().sign(&parsed.key).unwrap();

        // verify signature
        parsed
            .clone()
            .verify(
                provider.crypto(),
                &OpenMlsSignaturePublicKey::new(
                    public.clone().into(),
                    ciphersuite.signature_algorithm(),
                )
                .unwrap(),
            )
            .expect("Signature verification failed");

        // verify own signature
        parsed.signature = my_signature.0;
        parsed
            .verify(
                provider.crypto(),
                &OpenMlsSignaturePublicKey::new(public.into(), ciphersuite.signature_algorithm())
                    .unwrap(),
            )
            .expect("Signature verification failed");
    }

    // encrypt with label
    {
        let context = hex_to_bytes(&test.encrypt_with_label.context);
        let label = test.encrypt_with_label.label;
        let ciphertext = hex_to_bytes(&test.encrypt_with_label.ciphertext);
        let kem_output = hex_to_bytes(&test.encrypt_with_label.kem_output);
        let plaintext = hex_to_bytes(&test.encrypt_with_label.plaintext);
        let private = hex_to_bytes(&test.encrypt_with_label.r#priv);
        let public = hex_to_bytes(&test.encrypt_with_label.r#pub);

        // Check that decryption works.
        let decrypted_plaintext = hpke::decrypt_with_label(
            &private,
            &label,
            &context,
            &HpkeCiphertext {
                kem_output: kem_output.into(),
                ciphertext: ciphertext.into(),
            },
            ciphersuite,
            provider.crypto(),
        )
        .unwrap();
        assert_eq!(plaintext, decrypted_plaintext);

        // Check that encryption works.
        let my_ciphertext = hpke::encrypt_with_label(
            &public,
            &label,
            &context,
            &plaintext,
            ciphersuite,
            provider.crypto(),
        )
        .unwrap();
        let decrypted_plaintext = hpke::decrypt_with_label(
            &private,
            &label,
            &context,
            &my_ciphertext,
            ciphersuite,
            provider.crypto(),
        )
        .unwrap();
        assert_eq!(plaintext, decrypted_plaintext);
    }

    // Derive tree secret.
    {
        let secret = hex_to_bytes(&test.derive_tree_secret.secret);
        let label = test.derive_tree_secret.label;
        let generation = test.derive_tree_secret.generation;
        let length = test.derive_tree_secret.length;
        let out = hex_to_bytes(&test.derive_tree_secret.out);

        let tree_secret = derive_tree_secret(
            ciphersuite,
            &Secret::from_slice(&secret),
            &label,
            generation,
            length.into(),
            provider.crypto(),
        )
        .unwrap();

        assert_eq!(tree_secret.as_slice(), &out);
    }

    Ok(())
}

#[test]
fn read_test_vectors() {
    let _ = pretty_env_logger::try_init();

    log::debug!("Generating new basic crypto test vectors ...");

    let provider = OpenMlsRustCrypto::default();

    let tests: Vec<CryptoBasicsTestCase> = read_json!("../../../test_vectors/crypto-basics.json");
    for test in tests {
        match run_test_vector(test, &provider) {
            Ok(_) => {}
            Err(e) => panic!("Error while checking crypto basic test vector.\n{e:?}"),
        }
    }
}
