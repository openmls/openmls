//! # OpenMLS Delivery Service Library
//!
//! This library provides structs and necessary implementations to interact with
//! the OpenMLS DS.
//!
//! Clients are represented by the `ClientInfo` struct.

use std::collections::HashSet;

use openmls::prelude::{tls_codec::*, *};

/// Information about a client.
/// To register a new client create a new `ClientInfo` and send it to
/// `/clients/register`.
#[derive(Debug, Default, Clone)]
pub struct ClientInfo {
    pub client_name: String,
    pub key_packages: ClientKeyPackages,
    /// map of reserved key_packages [group_id, key_package_hash]
    pub reserved_key_pkg_hash: HashSet<Vec<u8>>,
    pub id: Vec<u8>,
    pub msgs: Vec<MlsMessageIn>,
    pub welcome_queue: Vec<MlsMessageIn>,
}

/// The DS returns a list of key packages for a client as `ClientKeyPackages`.
/// This is a tuple struct holding a vector of `(Vec<u8>, KeyPackage)` tuples,
/// where the first value is the key package hash (output of `KeyPackage::hash`)
/// and the second value is the corresponding key package.
#[derive(
    Debug,
    Default,
    Clone,
    PartialEq,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct ClientKeyPackages(pub TlsVecU32<(TlsByteVecU8, KeyPackageIn)>);

impl ClientInfo {
    /// Create a new `ClientInfo` struct for a given client name and vector of
    /// key packages with corresponding hashes.
    pub fn new(client_name: String, mut key_packages: Vec<(Vec<u8>, KeyPackageIn)>) -> Self {
        let key_package: KeyPackage = KeyPackage::from(key_packages[0].1.clone());
        let id = VLBytes::tls_deserialize_exact(
            key_package.leaf_node().credential().serialized_content(),
        )
        .unwrap();
        Self {
            client_name,
            id: id.into(),
            key_packages: ClientKeyPackages(
                key_packages
                    .drain(..)
                    .map(|(e1, e2)| (e1.into(), e2))
                    .collect::<Vec<(TlsByteVecU8, KeyPackageIn)>>()
                    .into(),
            ),
            reserved_key_pkg_hash: HashSet::new(),
            msgs: Vec::new(),
            welcome_queue: Vec::new(),
        }
    }

    /// The identity of a client is defined as the identity of the first key
    /// package right now.
    pub fn id(&self) -> &[u8] {
        self.id.as_slice()
    }

    /// Acquire a key package from the client's key packages
    /// Mark the key package hash ref as "reserved key package"
    /// The reserved hash ref will be used in DS::send_welcome and removed once welcome is distributed
    pub fn consume_kp(&mut self) -> Result<KeyPackageIn, String> {
        if self.key_packages.0.len() <= 1 {
            // We keep one keypackage to handle ClientInfo serialization/deserialization issues
            return Err("No more keypackage available".to_string());
        }
        match self.key_packages.0.pop() {
            Some(c) => {
                self.reserved_key_pkg_hash.insert(c.0.into_vec());
                Ok(c.1)
            }
            None => Err("No more keypackage available".to_string()),
        }
    }
}

/// An core group message.
/// This is an `MLSMessage` plus the list of recipients as a vector of client
/// names.
#[derive(Debug)]
pub struct GroupMessage {
    pub msg: MlsMessageIn,
    pub recipients: TlsVecU32<TlsByteVecU32>,
}

impl GroupMessage {
    /// Create a new `GroupMessage` taking an `MlsMessageIn` and slice of
    /// recipient names.
    pub fn new(msg: MlsMessageIn, recipients: &[Vec<u8>]) -> Self {
        Self {
            msg,
            recipients: recipients
                .iter()
                .map(|r| r.clone().into())
                .collect::<Vec<TlsByteVecU32>>()
                .into(),
        }
    }
}

impl tls_codec::Size for ClientInfo {
    fn tls_serialized_len(&self) -> usize {
        TlsByteSliceU16(self.client_name.as_bytes()).tls_serialized_len()
            + self.key_packages.tls_serialized_len()
    }
}

impl tls_codec::Serialize for ClientInfo {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let written = TlsByteSliceU16(self.client_name.as_bytes()).tls_serialize(writer)?;
        self.key_packages.tls_serialize(writer).map(|l| l + written)
    }
}

impl tls_codec::Deserialize for ClientInfo {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let client_name =
            String::from_utf8_lossy(TlsByteVecU16::tls_deserialize(bytes)?.as_slice()).into();
        let mut key_packages: Vec<(TlsByteVecU8, KeyPackageIn)> =
            TlsVecU32::<(TlsByteVecU8, KeyPackageIn)>::tls_deserialize(bytes)?.into();
        let key_packages = key_packages
            .drain(..)
            .map(|(e1, e2)| (e1.into(), e2))
            .collect();
        Ok(Self::new(client_name, key_packages))
    }
}

impl tls_codec::Size for GroupMessage {
    fn tls_serialized_len(&self) -> usize {
        self.msg.tls_serialized_len() + self.recipients.tls_serialized_len()
    }
}

impl tls_codec::Serialize for GroupMessage {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let written = self.msg.tls_serialize(writer)?;
        self.recipients.tls_serialize(writer).map(|l| l + written)
    }
}

impl tls_codec::Deserialize for GroupMessage {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let msg = MlsMessageIn::tls_deserialize(bytes)?;
        let recipients = TlsVecU32::<TlsByteVecU32>::tls_deserialize(bytes)?;
        Ok(Self { msg, recipients })
    }
}
