//! # X509 Credential
//!
//! An implementation of the x509 credential from the MLS spec.

use base64::Engine;
use openmls_basic_credential::SignatureKeyPair;
use percent_encoding::percent_decode_str;
use x509_cert::der::Decode;
use x509_cert::Certificate;

use openmls_traits::{
    crypto::OpenMlsCrypto,
    key_store::{MlsEntity, MlsEntityId},
    types::{CryptoError, SignatureScheme},
};

#[derive(std::fmt::Debug, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct CertificateKeyPair(pub SignatureKeyPair);

impl CertificateKeyPair {
    /// Constructs the `CertificateKeyPair` from a private key and a der encoded
    /// certificate chain
    pub fn new(sk: Vec<u8>, cert_chain: Vec<Vec<u8>>) -> Result<Self, CryptoError> {
        if cert_chain.is_empty() {
            return Err(CryptoError::IncompleteCertificateChain);
        }
        let pki_path = cert_chain.into_iter().try_fold(
            x509_cert::PkiPath::new(),
            |mut acc, cert_data| -> Result<x509_cert::PkiPath, CryptoError> {
                let cert = Certificate::from_der(&cert_data)
                    .map_err(|_| CryptoError::CertificateDecodingError)?;
                cert.is_valid()?;
                acc.push(cert);
                Ok(acc)
            },
        )?;

        let leaf = pki_path.first().ok_or(CryptoError::CryptoLibraryError)?;

        let signature_scheme = leaf.signature_scheme()?;
        let pk = leaf.public_key()?;

        let kp = SignatureKeyPair::try_from_raw(signature_scheme, sk, pk.to_vec())?;

        Ok(Self(kp))
    }
}

impl std::ops::Deref for CertificateKeyPair {
    type Target = SignatureKeyPair;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl secrecy::SerializableSecret for CertificateKeyPair {}

impl tls_codec::Size for CertificateKeyPair {
    fn tls_serialized_len(&self) -> usize {
        self.0.tls_serialized_len()
    }
}

impl tls_codec::Deserialize for CertificateKeyPair {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        SignatureKeyPair::tls_deserialize(bytes).map(Self)
    }
}

impl tls_codec::Serialize for CertificateKeyPair {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        self.0.tls_serialize(writer)
    }
}

impl openmls_traits::signatures::DefaultSigner for CertificateKeyPair {
    fn private_key(&self) -> &[u8] {
        self.0.private_key()
    }

    fn signature_scheme(&self) -> SignatureScheme {
        self.0.signature_scheme()
    }
}

impl MlsEntity for CertificateKeyPair {
    const ID: MlsEntityId = MlsEntityId::SignatureKeyPair;
}

pub trait X509Ext {
    fn is_valid(&self) -> Result<(), CryptoError>;

    fn is_time_valid(&self) -> Result<bool, CryptoError>;

    fn public_key(&self) -> Result<&[u8], CryptoError>;

    fn signature_scheme(&self) -> Result<SignatureScheme, CryptoError>;

    fn is_signed_by(
        &self,
        backend: &impl OpenMlsCrypto,
        issuer: &Certificate,
    ) -> Result<(), CryptoError>;

    fn identity(&self) -> Result<Vec<u8>, CryptoError>;
}

impl X509Ext for Certificate {
    fn is_valid(&self) -> Result<(), CryptoError> {
        if !self.is_time_valid()? {
            return Err(CryptoError::ExpiredCertificate);
        }
        Ok(())
    }

    fn is_time_valid(&self) -> Result<bool, CryptoError> {
        // 'not_before' < now < 'not_after'
        let validity = self.tbs_certificate().validity();
        let now = web_time::SystemTime::now();
        let now = now
            .duration_since(web_time::UNIX_EPOCH)
            .map_err(|_| CryptoError::TimeError)?;

        let is_nbf = now > validity.not_before.to_unix_duration();
        let is_naf = now < validity.not_after.to_unix_duration();
        Ok(is_nbf && is_naf)
    }

    fn public_key(&self) -> Result<&[u8], CryptoError> {
        self.tbs_certificate()
            .subject_public_key_info()
            .subject_public_key
            .as_bytes()
            .ok_or(CryptoError::IncompleteCertificate("spki"))
    }

    fn signature_scheme(&self) -> Result<SignatureScheme, CryptoError> {
        use const_oid::db::{
            rfc5912::{ID_EC_PUBLIC_KEY, SECP_256_R_1, SECP_384_R_1, SECP_521_R_1},
            rfc8410::{ID_ED_25519, ID_ED_448},
        };
        let spki = self.tbs_certificate().subject_public_key_info();
        let alg = spki.algorithm.oid;
        let params =
            spki.algorithm.parameters.as_ref().and_then(|param| {
                x509_cert::spki::ObjectIdentifier::from_bytes(param.value()).ok()
            });

        let scheme = match (alg, params) {
            (ID_ED_25519, None) => SignatureScheme::ED25519,
            (ID_ED_448, None) => SignatureScheme::ED448,
            (ID_EC_PUBLIC_KEY, Some(SECP_256_R_1)) => SignatureScheme::ECDSA_SECP256R1_SHA256,
            (ID_EC_PUBLIC_KEY, Some(SECP_384_R_1)) => SignatureScheme::ECDSA_SECP384R1_SHA384,
            (ID_EC_PUBLIC_KEY, Some(SECP_521_R_1)) => SignatureScheme::ECDSA_SECP521R1_SHA512,
            _ => return Err(CryptoError::UnsupportedSignatureScheme),
        };

        Ok(scheme)
    }

    fn is_signed_by(
        &self,
        backend: &impl OpenMlsCrypto,
        issuer: &Certificate,
    ) -> Result<(), CryptoError> {
        let issuer_pk = issuer.public_key()?;
        let cert_signature = self
            .signature()
            .as_bytes()
            .ok_or(CryptoError::InvalidCertificate)?;

        use x509_cert::der::Encode as _;
        let mut raw_tbs: Vec<u8> = vec![];
        self.tbs_certificate()
            .encode(&mut raw_tbs)
            .map_err(|_| CryptoError::CertificateEncodingError)?;
        let sc = issuer.signature_scheme()?;
        backend
            .verify_signature(sc, &raw_tbs, issuer_pk, cert_signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    fn identity(&self) -> Result<Vec<u8>, CryptoError> {
        let extensions = self.tbs_certificate().extensions();
        let extensions = extensions.as_ref().ok_or(CryptoError::InvalidCertificate)?;
        let san = extensions
            .iter()
            .find(|e| e.extn_id == const_oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME)
            .and_then(|e| {
                x509_cert::ext::pkix::SubjectAltName::from_der(e.extn_value.as_bytes()).ok()
            })
            .ok_or(CryptoError::InvalidCertificate)?;
        san.0
            .iter()
            .filter_map(|n| match n {
                x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(ia5_str) => {
                    Some(ia5_str.as_str())
                }
                _ => None,
            })
            .find_map(try_to_qualified_wire_client_id)
            .ok_or(CryptoError::InvalidCertificate)
    }
}

/// Turn 'wireapp://ZHpLZLZMROeMWp4sJlL2XA!dee090f1ed94e4c8@wire.com' into
/// '647a4b64-b64c-44e7-8c5a-9e2c2652f65c:dee090f1ed94e4c8@wire.com'
fn try_to_qualified_wire_client_id(client_id: &str) -> Option<Vec<u8>> {
    const COLON: u8 = 58;
    const WIRE_URI_SCHEME: &str = "wireapp://";

    let client_id = client_id.strip_prefix(WIRE_URI_SCHEME)?;
    let client_id = percent_decode_str(client_id).decode_utf8().ok()?;

    let (user_id, rest) = client_id.split_once('!')?;
    let user_id = to_hyphenated_user_id(user_id)?;

    let client_id = [&user_id[..], &[COLON], rest.as_bytes()].concat();
    Some(client_id)
}

fn to_hyphenated_user_id(user_id: &str) -> Option<[u8; uuid::fmt::Hyphenated::LENGTH]> {
    let user_id = base64::prelude::BASE64_URL_SAFE_NO_PAD
        .decode(user_id)
        .ok()?;

    let user_id = uuid::Uuid::from_slice(&user_id).ok()?;

    let mut buf = [0; uuid::fmt::Hyphenated::LENGTH];
    user_id.hyphenated().encode_lower(&mut buf);

    Some(buf)
}

#[test]
fn to_qualified_wire_client_id_should_work() {
    const EXPECTED: &str = "647a4b64-b64c-44e7-8c5a-9e2c2652f65c:dee090f1ed94e4c8@wire.com";

    let input = "wireapp://ZHpLZLZMROeMWp4sJlL2XA!dee090f1ed94e4c8@wire.com";
    let output = try_to_qualified_wire_client_id(input).unwrap();
    let output = std::str::from_utf8(&output).unwrap();
    assert_eq!(output, EXPECTED);

    // should percent decode the username before splitting it
    // here '!' is percent encoded into '%21'
    // that's the form in the x509 EE certificate
    let input = "wireapp://ZHpLZLZMROeMWp4sJlL2XA%21dee090f1ed94e4c8@wire.com";
    let output = try_to_qualified_wire_client_id(input).unwrap();
    let output = std::str::from_utf8(&output).unwrap();
    assert_eq!(output, EXPECTED);
}
