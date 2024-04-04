use crate::spec_types as private_types;
use openmls_spec_types as public_types;

impl private_types::key_package::KeyPackage {
    pub(in crate::spec_types) fn from_public(
        key_pkg: public_types::key_package::KeyPackage,
    ) -> Self {
        Self {
            payload: private_types::key_package::KeyPackageTbs::from_public(key_pkg.payload),
            signature: private_types::Signature::from_public(key_pkg.signature),
        }
    }
}

impl private_types::key_package::KeyPackageTbs {
    pub(in crate::spec_types) fn from_public(
        payload: public_types::key_package::KeyPackageTbs,
    ) -> Self {
        Self {
            protocol_version: private_types::ProtocolVersion::from_public(payload.protocol_version),
            ciphersuite: private_types::Ciphersuite::from_public(payload.ciphersuite),
            init_key: private_types::keys::InitKey::from_public(payload.init_key),
            leaf_node: private_types::tree::LeafNode::from_public(payload.leaf_node),
            extensions: private_types::extensions::Extensions::from_public(payload.extensions),
        }
    }
}

impl private_types::key_package::KeyPackageRef {
    pub(in crate::spec_types) fn from_public(
        key_pkg_ref: public_types::key_package::KeyPackageRef,
    ) -> Self {
        Self(private_types::HashReference::from_public(key_pkg_ref.0))
    }
}
