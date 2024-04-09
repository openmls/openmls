use crate::spec_types as private_types;
use openmls_spec_types as public_types;

mod proposals {
    use super::*;
    impl From<private_types::proposals::AddProposal> for openmls_spec_types::proposals::AddProposal {
        fn from(value: private_types::proposals::AddProposal) -> Self {
            openmls_spec_types::proposals::AddProposal {
                key_package: value.key_package.into(),
            }
        }
    }
    impl From<private_types::proposals::ProposalOrRefType>
        for openmls_spec_types::proposals::ProposalOrRefType
    {
        fn from(value: private_types::proposals::ProposalOrRefType) -> Self {
            match value {
                private_types::proposals::ProposalOrRefType::Proposal => {
                    openmls_spec_types::proposals::ProposalOrRefType::Proposal
                }
                private_types::proposals::ProposalOrRefType::Reference => {
                    openmls_spec_types::proposals::ProposalOrRefType::Reference
                }
            }
        }
    }

    impl From<private_types::proposals::ProposalType> for public_types::proposals::ProposalType {
        fn from(value: private_types::proposals::ProposalType) -> Self {
            match value {
                private_types::proposals::ProposalType::Add => {
                    public_types::proposals::ProposalType::Add
                }
                private_types::proposals::ProposalType::Update => {
                    public_types::proposals::ProposalType::Update
                }
                private_types::proposals::ProposalType::Remove => {
                    public_types::proposals::ProposalType::Remove
                }
                private_types::proposals::ProposalType::PreSharedKey => {
                    public_types::proposals::ProposalType::PreSharedKey
                }
                private_types::proposals::ProposalType::Reinit => {
                    public_types::proposals::ProposalType::Reinit
                }

                private_types::proposals::ProposalType::ExternalInit => {
                    public_types::proposals::ProposalType::ExternalInit
                }
                private_types::proposals::ProposalType::GroupContextExtensions => {
                    public_types::proposals::ProposalType::GroupContextExtensions
                }
                private_types::proposals::ProposalType::AppAck => {
                    public_types::proposals::ProposalType::AppAck
                }
                private_types::proposals::ProposalType::Unknown(n) => {
                    public_types::proposals::ProposalType::Unknown(n)
                }
            }
        }
    }
}

mod extensions {
    use super::*;

    impl From<private_types::extensions::ExtensionType> for public_types::extensions::ExtensionType {
        fn from(value: private_types::extensions::ExtensionType) -> Self {
            match value {
                private_types::extensions::ExtensionType::ApplicationId => {
                    public_types::extensions::ExtensionType::ApplicationId
                }
                private_types::extensions::ExtensionType::RatchetTree => {
                    public_types::extensions::ExtensionType::RatchetTree
                }
                private_types::extensions::ExtensionType::RequiredCapabilities => {
                    public_types::extensions::ExtensionType::RequiredCapabilities
                }
                private_types::extensions::ExtensionType::ExternalPub => {
                    public_types::extensions::ExtensionType::ExternalPub
                }
                private_types::extensions::ExtensionType::ExternalSenders => {
                    public_types::extensions::ExtensionType::ExternalSenders
                }
                private_types::extensions::ExtensionType::LastResort => {
                    public_types::extensions::ExtensionType::LastResort
                }
                private_types::extensions::ExtensionType::Unknown(n) => {
                    public_types::extensions::ExtensionType::Unknown(n)
                }
            }
        }
    }

    impl From<private_types::extensions::RequiredCapabilitiesExtension>
        for public_types::extensions::RequiredCapabilitiesExtension
    {
        fn from(value: private_types::extensions::RequiredCapabilitiesExtension) -> Self {
            openmls_spec_types::extensions::RequiredCapabilitiesExtension {
                extension_types: value
                    .extension_types
                    .into_iter()
                    .map(|t| t.into())
                    .collect(),
                proposal_types: value.proposal_types.into_iter().map(|t| t.into()).collect(),
                credential_types: value
                    .credential_types
                    .into_iter()
                    .map(|t| t.into())
                    .collect(),
            }
        }
    }

    impl From<private_types::extensions::Extensions> for openmls_spec_types::extensions::Extensions {
        fn from(value: private_types::extensions::Extensions) -> Self {
            openmls_spec_types::extensions::Extensions {
                unique: value.unique.into_iter().map(|e| e.into()).collect(),
            }
        }
    }
}

mod key_package {
    use super::*;
    impl From<private_types::key_package::KeyPackageTbs>
        for openmls_spec_types::key_package::KeyPackageTbs
    {
        fn from(value: private_types::key_package::KeyPackageTbs) -> Self {
            openmls_spec_types::key_package::KeyPackageTbs {
                protocol_version: value.protocol_version.into(),
                ciphersuite: value.ciphersuite.into(),
                init_key: value.init_key.into(),
                leaf_node: value.leaf_node.into(),
                extensions: value.extensions.into(),
            }
        }
    }

    impl From<private_types::key_package::KeyPackage> for openmls_spec_types::key_package::KeyPackage {
        fn from(value: private_types::key_package::KeyPackage) -> Self {
            openmls_spec_types::key_package::KeyPackage {
                payload: value.payload.into(),
                signature: value.signature.into(),
            }
        }
    }
}

mod keys {
    use super::*;
    impl From<private_types::keys::InitKey> for openmls_spec_types::keys::InitKey {
        fn from(value: crate::spec_types::keys::InitKey) -> Self {
            openmls_spec_types::keys::InitKey {
                key: value.key.into(),
            }
        }
    }
}

mod hpke {
    use super::*;

    impl From<private_types::hpke::HpkePublicKey> for public_types::hpke::HpkePublicKey {
        fn from(value: private_types::hpke::HpkePublicKey) -> Self {
            Self(value.0)
        }
    }
}
impl From<private_types::Signature> for openmls_spec_types::Signature {
    fn from(value: private_types::Signature) -> Self {
        openmls_spec_types::Signature { value: value.value }
    }
}

mod tree {
    use super::*;
    impl From<private_types::tree::Capabilities> for public_types::tree::Capabilities {
        fn from(value: private_types::tree::Capabilities) -> Self {
            openmls_spec_types::tree::Capabilities {
                versions: value.versions.into_iter().map(|v| v.into()).collect(),
                ciphersuites: value.ciphersuites.into_iter().map(|cs| cs.into()).collect(),
                extensions: value.extensions.into_iter().map(|et| et.into()).collect(),
                proposals: value.proposals.into_iter().map(|pt| pt.into()).collect(),
                credentials: value.credentials.into_iter().map(|c| c.into()).collect(),
            }
        }
    }
}

mod credential {
    use super::*;

    impl From<private_types::credential::CredentialType>
        for openmls_spec_types::credential::CredentialType
    {
        fn from(value: private_types::credential::CredentialType) -> Self {
            match value {
                private_types::credential::CredentialType::Basic => {
                    openmls_spec_types::credential::CredentialType::Basic
                }
                private_types::credential::CredentialType::X509 => {
                    openmls_spec_types::credential::CredentialType::X509
                }
                private_types::credential::CredentialType::Other(value) => {
                    openmls_spec_types::credential::CredentialType::Other(value)
                }
            }
        }
    }
}
