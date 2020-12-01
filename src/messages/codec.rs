//! Codec implementations for message structs.

use super::*;

impl Codec for GroupInfo {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        buffer.append(&mut self.unsigned_payload()?);
        self.signature.encode(buffer)?;
        Ok(())
    }
}

impl Codec for Commit {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU32, buffer, &self.proposals)?;
        self.path.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let proposals = decode_vec(VecSize::VecU32, cursor)?;
        let path = Option::<UpdatePath>::decode(cursor)?;
        Ok(Commit { proposals, path })
    }
}

impl Codec for ConfirmationTag {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.0)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let inner = decode_vec(VecSize::VecU8, cursor)?;
        Ok(ConfirmationTag(inner))
    }
}

impl Codec for PathSecret {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.path_secret.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let path_secret = Secret::decode(cursor)?;
        Ok(PathSecret { path_secret })
    }
}

impl Codec for EncryptedGroupSecrets {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.key_package_hash)?;
        self.encrypted_group_secrets.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let key_package_hash = decode_vec(VecSize::VecU8, cursor)?;
        let encrypted_group_secrets = HpkeCiphertext::decode(cursor)?;
        Ok(EncryptedGroupSecrets {
            key_package_hash,
            encrypted_group_secrets,
        })
    }
}

impl Codec for Welcome {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.version.encode(buffer)?;
        self.cipher_suite.name().encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.secrets)?;
        encode_vec(VecSize::VecU32, buffer, &self.encrypted_group_info)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let version = ProtocolVersion::decode(cursor)?;
        let cipher_suite = CiphersuiteName::decode(cursor)?;
        let secrets = decode_vec(VecSize::VecU32, cursor)?;
        let encrypted_group_info = decode_vec(VecSize::VecU32, cursor)?;
        Ok(Welcome {
            version,
            cipher_suite: Config::ciphersuite(cipher_suite)?,
            secrets,
            encrypted_group_info,
        })
    }
}

impl Codec for GroupSecrets {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.joiner_secret.encode(buffer)?;
        self.path_secret.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let joiner_secret = JoinerSecret::decode(cursor)?;
        let path_secret = Option::<PathSecret>::decode(cursor)?;
        Ok(GroupSecrets::new(joiner_secret, path_secret))
    }
}
