use crate::spec_types as private_types;
use crate::spec_types::conversion::unchecked::PrivateSpecType;
use openmls_spec_types as public_types;

impl PrivateSpecType for private_types::extensions::ExtensionType {
    type Public = public_types::extensions::ExtensionType;
    fn from_public_unchecked(extension_type: public_types::extensions::ExtensionType) -> Self {
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

impl PrivateSpecType for private_types::extensions::Extension {
    type Public = public_types::extensions::Extension;
    fn from_public_unchecked(extension: public_types::extensions::Extension) -> Self {
        match extension {
            public_types::extensions::Extension::ApplicationId(ext) => {
                private_types::extensions::Extension::ApplicationId(
                    private_types::extensions::ApplicationIdExtension::from_public_unchecked(ext),
                )
            }
            public_types::extensions::Extension::RatchetTree(ext) => {
                private_types::extensions::Extension::RatchetTree(
                    private_types::extensions::RatchetTreeExtension::from_public_unchecked(ext),
                )
            }
            public_types::extensions::Extension::RequiredCapabilities(ext) => {
                private_types::extensions::Extension::RequiredCapabilities(
                    private_types::extensions::RequiredCapabilitiesExtension::from_public_unchecked(
                        ext,
                    ),
                )
            }
            public_types::extensions::Extension::ExternalPub(ext) => {
                private_types::extensions::Extension::ExternalPub(
                    private_types::extensions::ExternalPubExtension::from_public_unchecked(ext),
                )
            }
            public_types::extensions::Extension::ExternalSenders(ext) => {
                private_types::extensions::Extension::ExternalSenders(
                    private_types::extensions::ExternalSendersExtension::from_public_unchecked(ext),
                )
            }
            public_types::extensions::Extension::LastResort(ext) => {
                private_types::extensions::Extension::LastResort(
                    private_types::extensions::LastResortExtension::from_public_unchecked(ext),
                )
            }
            public_types::extensions::Extension::Unknown(id, ext) => {
                private_types::extensions::Extension::Unknown(
                    id,
                    private_types::extensions::UnknownExtension::from_public_unchecked(ext),
                )
            }
        }
    }
}

impl PrivateSpecType for private_types::extensions::UnknownExtension {
    type Public = public_types::extensions::UnknownExtension;
    fn from_public_unchecked(
        unknown_extension: public_types::extensions::UnknownExtension,
    ) -> Self {
        Self(unknown_extension.0.into())
    }
}

impl PrivateSpecType for private_types::extensions::ApplicationIdExtension {
    type Public = public_types::extensions::ApplicationIdExtension;
    fn from_public_unchecked(app_id_ext: public_types::extensions::ApplicationIdExtension) -> Self {
        Self {
            key_id: app_id_ext.key_id.into(),
        }
    }
}

impl PrivateSpecType for private_types::extensions::RatchetTreeExtension {
    type Public = public_types::extensions::RatchetTreeExtension;
    fn from_public_unchecked(ext: public_types::extensions::RatchetTreeExtension) -> Self {
        Self {
            ratchet_tree: private_types::tree::RatchetTree::from_public_unchecked(ext.ratchet_tree),
        }
    }
}

impl PrivateSpecType for private_types::extensions::RequiredCapabilitiesExtension {
    type Public = public_types::extensions::RequiredCapabilitiesExtension;
    fn from_public_unchecked(ext: public_types::extensions::RequiredCapabilitiesExtension) -> Self {
        Self {
            extension_types: ext
                .extension_types
                .into_iter()
                .map(private_types::extensions::ExtensionType::from_public_unchecked)
                .collect(),
            proposal_types: ext
                .proposal_types
                .into_iter()
                .map(private_types::proposals::ProposalType::from_public_unchecked)
                .collect(),
            credential_types: ext
                .credential_types
                .into_iter()
                .map(private_types::credential::CredentialType::from_public_unchecked)
                .collect(),
        }
    }
}

impl PrivateSpecType for private_types::extensions::ExternalPubExtension {
    type Public = public_types::extensions::ExternalPubExtension;
    fn from_public_unchecked(ext: public_types::extensions::ExternalPubExtension) -> Self {
        Self {
            external_pub: private_types::hpke::HpkePublicKey::from_public_unchecked(
                ext.external_pub,
            ),
        }
    }
}

impl PrivateSpecType for private_types::extensions::ExternalSendersExtension {
    type Public = public_types::extensions::ExternalSendersExtension;
    fn from_public_unchecked(ext: public_types::extensions::ExternalSendersExtension) -> Self {
        Self(
            ext.into_iter()
                .map(private_types::extensions::ExternalSender::from_public_unchecked)
                .collect(),
        )
    }
}

impl PrivateSpecType for private_types::extensions::ExternalSender {
    type Public = public_types::extensions::ExternalSender;
    fn from_public_unchecked(external_sender: public_types::extensions::ExternalSender) -> Self {
        Self {
            signature_key: private_types::keys::SignaturePublicKey::from_public_unchecked(
                external_sender.signature_key,
            ),
            credential: private_types::credential::Credential::from_public_unchecked(
                external_sender.credential,
            ),
        }
    }
}

impl PrivateSpecType for private_types::extensions::LastResortExtension {
    type Public = public_types::extensions::LastResortExtension;
    fn from_public_unchecked(ext: public_types::extensions::LastResortExtension) -> Self {
        Self {}
    }
}

impl PrivateSpecType for private_types::extensions::Extensions {
    type Public = public_types::extensions::Extensions;
    fn from_public_unchecked(exts: public_types::extensions::Extensions) -> Self {
        Self {
            unique: exts
                .unique
                .into_iter()
                .map(private_types::extensions::Extension::from_public_unchecked)
                .collect(),
        }
    }
}

impl PrivateSpecType for private_types::extensions::SenderExtensionIndex {
    type Public = public_types::extensions::SenderExtensionIndex;
    fn from_public_unchecked(index: public_types::extensions::SenderExtensionIndex) -> Self {
        Self(index.0)
    }
}
