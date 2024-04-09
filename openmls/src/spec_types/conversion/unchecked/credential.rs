use crate::spec_types as private_types;
use crate::spec_types::conversion::unchecked::PrivateSpecType;
use openmls_spec_types as public_types;

impl PrivateSpecType for private_types::credential::CredentialType {
    type Public = public_types::credential::CredentialType;
    fn from_public_unchecked(credential_type: public_types::credential::CredentialType) -> Self {
        match credential_type {
            public_types::credential::CredentialType::Basic => {
                private_types::credential::CredentialType::Basic
            }
            public_types::credential::CredentialType::X509 => {
                private_types::credential::CredentialType::X509
            }
            public_types::credential::CredentialType::Other(n) => {
                private_types::credential::CredentialType::Other(n)
            }
        }
    }
}

impl PrivateSpecType for private_types::credential::Credential {
    type Public = public_types::credential::Credential;
    fn from_public_unchecked(credential: public_types::credential::Credential) -> Self {
        Self {
            credential_type: private_types::credential::CredentialType::from_public_unchecked(
                credential.credential_type,
            ),
            serialized_credential_content: credential.serialized_credential_content.into(),
        }
    }
}
