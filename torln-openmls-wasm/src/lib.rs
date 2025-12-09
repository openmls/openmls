mod utils;

#[cfg(test)]
mod tests;

use js_sys::Uint8Array;
use openmls::{
    credentials::{BasicCredential, CredentialWithKey},
    framing::{MlsMessageBodyIn, MlsMessageIn, MlsMessageOut},
    group::{GroupId, MlsGroup, MlsGroupJoinConfig, StagedWelcome},
    key_packages::KeyPackage as OpenMlsKeyPackage,
    prelude::SignatureScheme,
    treesync::RatchetTreeIn,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{types::Ciphersuite, OpenMlsProvider};
use std::convert::TryInto;
use tls_codec::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);

    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

/// The ciphersuite used here. Fixed in order to reduce the binary size.
static CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

#[wasm_bindgen]
#[derive(Default)]
pub struct Provider(OpenMlsRustCrypto);

impl AsRef<OpenMlsRustCrypto> for Provider {
    fn as_ref(&self) -> &OpenMlsRustCrypto {
        &self.0
    }
}

impl AsMut<OpenMlsRustCrypto> for Provider {
    fn as_mut(&mut self) -> &mut OpenMlsRustCrypto {
        &mut self.0
    }
}

#[wasm_bindgen]
impl Provider {
    #[wasm_bindgen(constructor)]
    pub fn create(seed: Option<Vec<u8>>) -> Result<Self, JsError> {
        if let Some(seed_vec) = seed {
            if seed_vec.len() != 32 {
                return Err(JsError::new("Seed must be exactly 32 bytes"));
            }
            let provider = OpenMlsRustCrypto::with_seed(&seed_vec);
            Ok(Self(provider))
        } else {
            Ok(Self::default())
        }
    }

    /// Export the entire provider storage as a compact binary blob for backup
    #[wasm_bindgen(js_name = exportStorage)]
    pub fn export_storage(&self) -> Result<Vec<u8>, JsError> {
        let storage = self.0.storage();
        let values = storage
            .values
            .read()
            .map_err(|e| JsError::new(&format!("Failed to read storage: {}", e)))?;

        // Binary format (little endian):
        // [u32 entry_count] then for each entry: [u32 key_len][u32 val_len][key bytes][val bytes]
        let mut out = Vec::with_capacity(4 + values.len() * 8);
        out.extend_from_slice(&(values.len() as u32).to_le_bytes());

        for (key, value) in values.iter() {
            out.extend_from_slice(&(key.len() as u32).to_le_bytes());
            out.extend_from_slice(&(value.len() as u32).to_le_bytes());
            out.extend_from_slice(key);
            out.extend_from_slice(value);
        }

        Ok(out)
    }

    /// Import storage from a previously exported binary blob
    #[wasm_bindgen(js_name = importStorage)]
    pub fn import_storage(&self, storage_bytes: &[u8]) -> Result<(), JsError> {
        let storage = self.0.storage();
        let mut values = storage
            .values
            .write()
            .map_err(|e| JsError::new(&format!("Failed to write to storage: {}", e)))?;

        // Parse the binary format described in `export_storage`.
        let mut cursor = 0usize;
        let len = storage_bytes.len();

        // Need at least 4 bytes for the entry count
        if len < 4 {
            return Err(JsError::new("Storage data too short"));
        }

        let read_u32 = |data: &[u8]| -> u32 { u32::from_le_bytes(data.try_into().unwrap()) };

        let entry_count = read_u32(&storage_bytes[cursor..cursor + 4]) as usize;
        cursor += 4;

        for _ in 0..entry_count {
            if cursor + 8 > len {
                return Err(JsError::new("Corrupted storage: truncated lengths"));
            }

            let key_len = read_u32(&storage_bytes[cursor..cursor + 4]) as usize;
            cursor += 4;
            let val_len = read_u32(&storage_bytes[cursor..cursor + 4]) as usize;
            cursor += 4;

            if cursor + key_len + val_len > len {
                return Err(JsError::new("Corrupted storage: truncated key/value"));
            }

            let key = storage_bytes[cursor..cursor + key_len].to_vec();
            cursor += key_len;
            let value = storage_bytes[cursor..cursor + val_len].to_vec();
            cursor += val_len;

            values.insert(key, value);
        }

        Ok(())
    }

    #[wasm_bindgen(js_name = createFromStorage)]
    pub fn create_from_storage(
        seed: Option<Vec<u8>>,
        storage_bytes: &[u8],
    ) -> Result<Self, JsError> {
        let provider = Self::create(seed)?;
        provider.import_storage(storage_bytes)?;
        Ok(provider)
    }
}

#[wasm_bindgen]
pub struct Identity {
    credential_with_key: CredentialWithKey,
    keypair: openmls_basic_credential::SignatureKeyPair,
}

#[wasm_bindgen]
impl Identity {
    #[wasm_bindgen(constructor)]
    pub fn create(
        provider: &Provider,
        name: &str,
        keypair_bytes: Option<Vec<u8>>,
    ) -> Result<Identity, JsError> {
        let signature_scheme = SignatureScheme::ED25519;
        let identity = name.bytes().collect();
        let credential = BasicCredential::new(identity);

        let keypair = if let Some(bytes) = keypair_bytes {
            SignatureKeyPair::tls_deserialize(&mut bytes.as_slice())?
        } else {
            SignatureKeyPair::new(signature_scheme)?
        };

        keypair.store(provider.0.storage())?;

        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: keypair.public().into(),
        };

        Ok(Identity {
            credential_with_key,
            keypair,
        })
    }

    #[wasm_bindgen(js_name = getKeyPackage)]
    pub fn get_key_package(&self, provider: &Provider) -> KeyPackage {
        KeyPackage(
            OpenMlsKeyPackage::builder()
                .build(
                    CIPHERSUITE,
                    &provider.0,
                    &self.keypair,
                    self.credential_with_key.clone(),
                )
                .unwrap()
                .key_package()
                .clone(),
        )
    }

    #[wasm_bindgen(js_name = getPublicKeyBytes)]
    pub fn get_public_key_bytes(&self) -> Vec<u8> {
        self.keypair.public().to_vec()
    }

    /// Export the keypair as bytes for backup/recovery purposes
    #[wasm_bindgen(js_name = exportKeypairBytes)]
    pub fn export_keypair_bytes(&self) -> Result<Vec<u8>, JsError> {
        Ok(self.keypair.tls_serialize_detached()?)
    }

    #[wasm_bindgen(js_name = getCredentialBytes)]
    pub fn get_credential_bytes(&self) -> Result<Vec<u8>, JsError> {
        Ok(self
            .credential_with_key
            .credential
            .tls_serialize_detached()?)
    }
}

#[wasm_bindgen]
pub struct Group {
    mls_group: MlsGroup,
}

#[wasm_bindgen]
pub struct AddMessages {
    proposal: Uint8Array,
    commit: Uint8Array,
    welcome: Uint8Array,
}

#[cfg(test)]
pub(crate) struct NativeAddMessages {
    pub(crate) proposal: Vec<u8>,
    pub(crate) commit: Vec<u8>,
    pub(crate) welcome: Vec<u8>,
}

#[wasm_bindgen]
impl AddMessages {
    #[wasm_bindgen(getter)]
    pub fn proposal(&self) -> Uint8Array {
        self.proposal.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn commit(&self) -> Uint8Array {
        self.commit.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn welcome(&self) -> Uint8Array {
        self.welcome.clone()
    }
}

#[wasm_bindgen]
impl Group {
    #[wasm_bindgen(js_name = createNew)]
    pub fn create_new(provider: &Provider, founder: &Identity, group_id: &str) -> Group {
        let group_id_bytes = group_id.bytes().collect::<Vec<_>>();

        let mls_group = MlsGroup::builder()
            .ciphersuite(CIPHERSUITE)
            .with_group_id(GroupId::from_slice(&group_id_bytes))
            .build(
                &provider.0,
                &founder.keypair,
                founder.credential_with_key.clone(),
            )
            .unwrap();

        Group { mls_group }
    }

    /// Load an existing group from provider storage by group ID
    #[wasm_bindgen(js_name = loadFromStorage)]
    pub fn load_from_storage(provider: &Provider, group_id: &str) -> Result<Group, JsError> {
        let group_id_bytes = group_id.bytes().collect::<Vec<_>>();
        let group_id_obj = GroupId::from_slice(&group_id_bytes);

        let mls_group = MlsGroup::load(provider.0.storage(), &group_id_obj)
            .map_err(|e| JsError::new(&format!("Failed to load group: {}", e)))?
            .ok_or_else(|| JsError::new("Group not found in storage"))?;

        Ok(Group { mls_group })
    }

    #[wasm_bindgen(js_name = groupId)]
    pub fn group_id(&self) -> String {
        String::from_utf8_lossy(self.mls_group.group_id().as_slice()).to_string()
    }

    pub fn join(
        provider: &Provider,
        mut welcome: &[u8],
        ratchet_tree: RatchetTree,
    ) -> Result<Group, JsError> {
        let welcome = match MlsMessageIn::tls_deserialize(&mut welcome)?.extract() {
            MlsMessageBodyIn::Welcome(welcome) => Ok(welcome),
            other => Err(openmls::error::ErrorString::from(format!(
                "expected a message of type welcome, got {other:?}",
            ))),
        }?;
        let config = MlsGroupJoinConfig::builder().build();
        let mls_group =
            StagedWelcome::new_from_welcome(&provider.0, &config, welcome, Some(ratchet_tree.0))?
                .into_group(&provider.0)?;

        Ok(Group { mls_group })
    }

    #[wasm_bindgen(js_name = exportRatchetTree)]
    pub fn export_ratchet_tree(&self) -> RatchetTree {
        RatchetTree(self.mls_group.export_ratchet_tree().into())
    }

    #[wasm_bindgen(js_name = proposeAndCommitAdd)]
    pub fn propose_and_commit_add(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        new_member: &KeyPackage,
    ) -> Result<AddMessages, JsError> {
        let (proposal_msg, _proposal_ref) =
            self.mls_group
                .propose_add_member(provider.as_ref(), &sender.keypair, &new_member.0)?;

        let (commit_msg, welcome_msg, _group_info) = self
            .mls_group
            .commit_to_pending_proposals(&provider.0, &sender.keypair)?;

        let welcome_msg = welcome_msg.ok_or(NoWelcomeError)?;

        let proposal = mls_message_to_uint8array(&proposal_msg);
        let commit = mls_message_to_uint8array(&commit_msg);
        let welcome = mls_message_to_uint8array(&welcome_msg);

        Ok(AddMessages {
            proposal,
            commit,
            welcome,
        })
    }

    #[wasm_bindgen(js_name = mergePendingCommit)]
    pub fn merge_pending_commit(&mut self, provider: &mut Provider) -> Result<(), JsError> {
        self.mls_group
            .merge_pending_commit(provider.as_mut())
            .map_err(|e| e.into())
    }

    #[wasm_bindgen(js_name = createMessage)]
    pub fn create_message(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        msg: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let msg_out = &self
            .mls_group
            .create_message(provider.as_ref(), &sender.keypair, msg)?;
        let mut serialized = vec![];
        msg_out.tls_serialize(&mut serialized)?;
        Ok(serialized)
    }

    #[wasm_bindgen(js_name = processMessage)]
    pub fn process_message(
        &mut self,
        provider: &mut Provider,
        mut msg: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let msg = MlsMessageIn::tls_deserialize(&mut msg).unwrap();

        let msg = match msg.extract() {
            openmls::framing::MlsMessageBodyIn::PublicMessage(msg) => {
                self.mls_group.process_message(provider.as_ref(), msg)?
            }

            openmls::framing::MlsMessageBodyIn::PrivateMessage(msg) => {
                self.mls_group.process_message(provider.as_ref(), msg)?
            }
            openmls::framing::MlsMessageBodyIn::Welcome(_) => todo!(),
            openmls::framing::MlsMessageBodyIn::GroupInfo(_) => todo!(),
            openmls::framing::MlsMessageBodyIn::KeyPackage(_) => todo!(),
        };

        match msg.into_content() {
            openmls::framing::ProcessedMessageContent::ApplicationMessage(app_msg) => {
                Ok(app_msg.into_bytes())
            }
            openmls::framing::ProcessedMessageContent::ProposalMessage(_)
            | openmls::framing::ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                Ok(vec![])
            }
            openmls::framing::ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                self.mls_group
                    .merge_staged_commit(provider.as_mut(), *staged_commit)?;
                Ok(vec![])
            }
        }
    }

    #[wasm_bindgen(js_name = exportSecret)]
    pub fn export_secret(
        &self,
        provider: &Provider,
        label: &str,
        context: &[u8],
        key_length: usize,
    ) -> Result<Vec<u8>, JsError> {
        self.mls_group
            .export_secret(provider.as_ref().crypto(), label, context, key_length)
            .map_err(|e| {
                println!("export key error: {e}");
                e.into()
            })
    }

    #[wasm_bindgen(js_name = getEpoch)]
    pub fn get_epoch(&self) -> u32 {
        self.mls_group.epoch().as_u64() as u32
    }
}

#[cfg(test)]
impl Group {
    pub(crate) fn native_propose_and_commit_add(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        new_member: &KeyPackage,
    ) -> Result<NativeAddMessages, JsError> {
        let (proposal_msg, _proposal_ref) =
            self.mls_group
                .propose_add_member(provider.as_ref(), &sender.keypair, &new_member.0)?;

        let (commit_msg, welcome_msg, _group_info) = self
            .mls_group
            .commit_to_pending_proposals(provider.as_ref(), &sender.keypair)?;

        let welcome_msg = welcome_msg.ok_or(NoWelcomeError)?;

        let proposal = mls_message_to_u8vec(&proposal_msg);
        let commit = mls_message_to_u8vec(&commit_msg);
        let welcome = mls_message_to_u8vec(&welcome_msg);

        Ok(NativeAddMessages {
            proposal,
            commit,
            welcome,
        })
    }

    pub(crate) fn native_join(
        provider: &Provider,
        mut welcome: &[u8],
        ratchet_tree: RatchetTree,
    ) -> Group {
        let welcome = match MlsMessageIn::tls_deserialize(&mut welcome)
            .unwrap()
            .extract()
        {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => panic!("expected a message of type welcome"),
        };
        let config = MlsGroupJoinConfig::builder().build();
        let mls_group = StagedWelcome::new_from_welcome(
            provider.as_ref(),
            &config,
            welcome,
            Some(ratchet_tree.0),
        )
        .unwrap()
        .into_group(provider.as_ref())
        .unwrap();

        Group { mls_group }
    }
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct NoWelcomeError;

impl std::fmt::Display for NoWelcomeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no welcome")
    }
}

impl std::error::Error for NoWelcomeError {}

#[wasm_bindgen]
pub struct KeyPackage(OpenMlsKeyPackage);

#[wasm_bindgen]
impl KeyPackage {
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<Vec<u8>, JsError> {
        Ok(self.0.tls_serialize_detached()?)
    }
}

#[wasm_bindgen]
pub struct RatchetTree(RatchetTreeIn);

fn mls_message_to_uint8array(msg: &MlsMessageOut) -> Uint8Array {
    // see https://github.com/rustwasm/wasm-bindgen/issues/1619#issuecomment-505065294

    let mut serialized = vec![];
    msg.tls_serialize(&mut serialized).unwrap();

    unsafe { Uint8Array::new(&Uint8Array::view(&serialized)) }
}

#[cfg(test)]
pub(crate) fn mls_message_to_u8vec(msg: &MlsMessageOut) -> Vec<u8> {
    // see https://github.com/rustwasm/wasm-bindgen/issues/1619#issuecomment-505065294

    let mut serialized = vec![];
    msg.tls_serialize(&mut serialized).unwrap();
    serialized
}
