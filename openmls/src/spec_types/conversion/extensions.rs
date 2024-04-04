use crate::spec_types as private_types;
use openmls_spec_types as public_types;

impl private_types::extensions::ExtensionType {
    pub(in crate::spec_types) fn from_public(
        extension_type: public_types::extensions::ExtensionType,
    ) -> Self {
        match extension_type {
            public_types::extensions::ExtensionType::ApplicationId => {
                private_types::extensions::ExtensionType::ApplicationId
            }
            public_types::extensions::ExtensionType::RatchetTree => {
                private_types::extensions::ExtensionType::RatchetTree
            }
            public_types::extensions::ExtensionType::RequiredCapabilities => {
                private_types::extensions::ExtensionType::RequiredCapabilities
            }
            public_types::extensions::ExtensionType::ExternalPub => {
                private_types::extensions::ExtensionType::ExternalPub
            }
            public_types::extensions::ExtensionType::ExternalSenders => {
                private_types::extensions::ExtensionType::ExternalSenders
            }
            public_types::extensions::ExtensionType::LastResort => {
                private_types::extensions::ExtensionType::LastResort
            }
            public_types::extensions::ExtensionType::Unknown(n) => {
                private_types::extensions::ExtensionType::Unknown(n)
            }
        }
    }
}

impl private_types::extensions::Extension {
    pub(in crate::spec_types) fn from_public(
        extension: public_types::extensions::Extension,
    ) -> Self {
        match extension {
            public_types::extensions::Extension::ApplicationId(ext) => {
                private_types::extensions::Extension::ApplicationId(
                    private_types::extensions::ApplicationIdExtension::from_public(ext),
                )
            }
            public_types::extensions::Extension::RatchetTree(ext) => {
                private_types::extensions::Extension::RatchetTree(
                    private_types::extensions::RatchetTreeExtension::from_public(ext),
                )
            }
            public_types::extensions::Extension::RequiredCapabilities(ext) => {
                private_types::extensions::Extension::RequiredCapabilities(
                    private_types::extensions::RequiredCapabilitiesExtension::from_public(ext),
                )
            }
            public_types::extensions::Extension::ExternalPub(ext) => {
                private_types::extensions::Extension::ExternalPub(
                    private_types::extensions::ExternalPubExtension::from_public(ext),
                )
            }
            public_types::extensions::Extension::ExternalSenders(ext) => {
                private_types::extensions::Extension::ExternalSenders(
                    private_types::extensions::ExternalSendersExtension::from_public(ext),
                )
            }
            public_types::extensions::Extension::LastResort(ext) => {
                private_types::extensions::Extension::LastResort(
                    private_types::extensions::LastResortExtension::from_public(ext),
                )
            }
            public_types::extensions::Extension::Unknown(id, ext) => {
                private_types::extensions::Extension::Unknown(
                    id,
                    private_types::extensions::UnknownExtension::from_public(ext),
                )
            }
        }
    }
}

impl private_types::extensions::UnknownExtension {
    pub(in crate::spec_types) fn from_public(
        unknown_extension: public_types::extensions::UnknownExtension,
    ) -> Self {
        Self(unknown_extension.0.into())
    }
}

impl private_types::extensions::ApplicationIdExtension {
    pub(in crate::spec_types) fn from_public(
        app_id_ext: public_types::extensions::ApplicationIdExtension,
    ) -> Self {
        Self {
            key_id: app_id_ext.key_id.into(),
        }
    }
}

impl private_types::extensions::RatchetTreeExtension {
    pub(in crate::spec_types) fn from_public(
        ext: public_types::extensions::RatchetTreeExtension,
    ) -> Self {
        Self {
            ratchet_tree: private_types::tree::RatchetTree::from_public(ext.ratchet_tree),
        }
    }
}

impl private_types::extensions::RequiredCapabilitiesExtension {
    pub(in crate::spec_types) fn from_public(
        ext: public_types::extensions::RequiredCapabilitiesExtension,
    ) -> Self {
        Self {
            extension_types: ext
                .extension_types
                .into_iter()
                .map(private_types::extensions::ExtensionType::from_public)
                .collect(),
            proposal_types: ext
                .proposal_types
                .into_iter()
                .map(private_types::proposals::ProposalType::from_public)
                .collect(),
            credential_types: ext
                .credential_types
                .into_iter()
                .map(private_types::credential::CredentialType::from_public)
                .collect(),
        }
    }
}

impl private_types::extensions::ExternalPubExtension {
    pub(in crate::spec_types) fn from_public(
        ext: public_types::extensions::ExternalPubExtension,
    ) -> Self {
        Self {
            external_pub: private_types::hpke::HpkePublicKey::from_public(ext.external_pub),
        }
    }
}

impl private_types::extensions::ExternalSendersExtension {
    pub(in crate::spec_types) fn from_public(
        ext: public_types::extensions::ExternalSendersExtension,
    ) -> Self {
        Self(
            ext.into_iter()
                .map(private_types::extensions::ExternalSender::from_public)
                .collect(),
        )
    }
}

impl private_types::extensions::ExternalSender {
    pub(in crate::spec_types) fn from_public(
        external_sender: public_types::extensions::ExternalSender,
    ) -> Self {
        Self {
            signature_key: private_types::keys::SignaturePublicKey::from_public(
                external_sender.signature_key,
            ),
            credential: private_types::credential::Credential::from_public(
                external_sender.credential,
            ),
        }
    }
}

impl private_types::extensions::LastResortExtension {
    pub(in crate::spec_types) fn from_public(
        ext: public_types::extensions::LastResortExtension,
    ) -> Self {
        Self {}
    }
}
