use crate::spec_types as private_types;
use openmls_spec_types as public_types;

impl private_types::credential::CredentialType {
    pub(in crate::spec_types) fn from_public(
        credential_type: public_types::credential::CredentialType,
    ) -> Self {
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

impl private_types::credential::Credential {
    pub(in crate::spec_types) fn from_public(
        credential: public_types::credential::Credential,
    ) -> Self {
        Self {
            credential_type: private_types::credential::CredentialType::from_public(
                credential.credential_type,
            ),
            serialized_credential_content: credential.serialized_credential_content.into(),
        }
    }
}
