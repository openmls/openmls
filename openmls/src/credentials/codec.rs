use super::*;

implement_codec! {
    CredentialType,
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u16).encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        if let Ok(credential_type) = Self::try_from(u16::decode(cursor)?) {
            Ok(credential_type)
        } else {
            Err(CodecError::DecodingError)
        }
    }
}

implement_codec! {
    Credential,
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        match &self.credential {
            MlsCredentialType::Basic(basic_credential) => {
                CredentialType::Basic.encode(buffer)?;
                basic_credential.encode(buffer)?;
            }
            // TODO #134: implement encoding for X509 certificates
            MlsCredentialType::X509(_) => panic!("X509 certificates are not yet implemented."),
        }
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let credential_type = match CredentialType::try_from(u16::decode(cursor)?) {
            Ok(c) => c,
            Err(_) => return Err(CodecError::DecodingError),
        };
        match credential_type {
            CredentialType::Basic => Ok(Credential::from(MlsCredentialType::Basic(
                BasicCredential::decode(cursor)?,
            ))),
            _ => Err(CodecError::DecodingError),
        }
    }
}

implement_codec! {
    BasicCredential,
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.identity)?;
        self.signature_scheme.encode(buffer)?;
        self.public_key.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let identity = decode_vec(VecSize::VecU16, cursor)?;
        let signature_scheme = SignatureScheme::decode(cursor)?;
        let public_key_bytes = decode_vec(VecSize::VecU16, cursor)?;
        let public_key = match SignaturePublicKey::new(public_key_bytes, signature_scheme) {
            Ok(public_key) => public_key,
            Err(_) => return Err(CodecError::DecodingError),
        };
        Ok(BasicCredential {
            identity,
            signature_scheme,
            public_key,
        })
    }
}
