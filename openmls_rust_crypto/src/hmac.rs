use hmac::Mac;
use openmls_traits::types;
use openmls_traits::types::{CryptoError, HashType};
use sha2::{Sha256, Sha384, Sha512};
use tls_codec::SecretVLBytes;

type HmacSha256 = hmac::Hmac<Sha256>;
type HmacSha384 = hmac::Hmac<Sha384>;
type HmacSha512 = hmac::Hmac<Sha512>;

macro_rules! hmac_digest {
    ($hash_t:ty, $key:ident, $message:ident) => {{
        let mut hmac = <$hash_t>::new_from_slice($key).map_err(|_e| CryptoError::InvalidLength)?;
        hmac.update($message);
        hmac.finalize().into_bytes().into_iter().collect()
    }};
}

pub(crate) fn hmac(
    hash_type: HashType,
    key: &[u8],
    message: &[u8],
) -> Result<SecretVLBytes, types::CryptoError> {
    let digest: Vec<u8> = match hash_type {
        HashType::Sha2_256 => hmac_digest!(HmacSha256, key, message),
        HashType::Sha2_384 => hmac_digest!(HmacSha384, key, message),
        HashType::Sha2_512 => hmac_digest!(HmacSha512, key, message),
    };
    Ok(SecretVLBytes::new(digest))
}
