mod utils;

use js_sys::Uint8Array;
use openmls::{
    credentials::{BasicCredential, CredentialWithKey},
    framing::{MlsMessageBodyIn, MlsMessageIn, MlsMessageOut},
    group::{GroupId, MlsGroup, MlsGroupJoinConfig, StagedWelcome},
    key_packages::KeyPackage as OpenMlsKeyPackage,
    prelude::{LeafNodeParameters, SenderRatchetConfiguration, SignatureScheme},
    treesync::RatchetTreeIn,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{types::Ciphersuite, OpenMlsProvider};
use tls_codec::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);

    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

static CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

const MAX_PAST_EPOCHS: usize = 5;

const PADDING_SIZE: usize = 128;

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
    pub fn new() -> Self {
        Self::default()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, JsError> {
        let values = self.0.storage().values.read().unwrap();
        let mut buf = Vec::new();
        let count = (values.len() as u64).to_be_bytes();
        buf.extend_from_slice(&count);
        for (k, v) in values.iter() {
            buf.extend_from_slice(&(k.len() as u64).to_be_bytes());
            buf.extend_from_slice(&(v.len() as u64).to_be_bytes());
            buf.extend_from_slice(k);
            buf.extend_from_slice(v);
        }
        Ok(buf)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Provider, JsError> {
        use std::collections::HashMap;
        let mut cursor = bytes;
        let read_u64 = |c: &mut &[u8]| -> Result<u64, JsError> {
            if c.len() < 8 {
                return Err(JsError::new("unexpected end of provider bytes"));
            }
            let (chunk, rest) = c.split_at(8);
            *c = rest;
            Ok(u64::from_be_bytes(chunk.try_into().unwrap()))
        };
        let count = read_u64(&mut cursor)? as usize;
        let mut map = HashMap::with_capacity(count);
        for _ in 0..count {
            let k_len = read_u64(&mut cursor)? as usize;
            let v_len = read_u64(&mut cursor)? as usize;
            if cursor.len() < k_len + v_len {
                return Err(JsError::new("unexpected end of provider bytes"));
            }
            let (k, rest) = cursor.split_at(k_len);
            let (v, rest) = rest.split_at(v_len);
            cursor = rest;
            map.insert(k.to_vec(), v.to_vec());
        }
        let provider = Provider::default();
        {
            let mut storage = provider.0.storage().values.write().unwrap();
            *storage = map;
        }
        Ok(provider)
    }
}

#[wasm_bindgen]
pub fn greet() {
    alert("Hello, openmls!");
}

#[derive(serde::Serialize, serde::Deserialize)]
struct IdentityData {
    name: Vec<u8>,
    keypair: SignatureKeyPair,
}

#[wasm_bindgen]
pub struct Identity {
    credential_with_key: CredentialWithKey,
    keypair: SignatureKeyPair,
}

#[wasm_bindgen]
impl Identity {
    #[wasm_bindgen(constructor)]
    pub fn new(provider: &Provider, name: &str) -> Result<Identity, JsError> {
        let signature_scheme = SignatureScheme::ED25519;
        let identity: Vec<u8> = name.bytes().collect();
        let credential = BasicCredential::new(identity);
        let keypair = SignatureKeyPair::new(signature_scheme)?;

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

    pub fn to_bytes(&self) -> Result<Vec<u8>, JsError> {
        let name = self
            .credential_with_key
            .credential
            .serialized_content()
            .to_vec();
        let data = IdentityData {
            name,
            keypair: self.keypair.clone(),
        };
        serde_json::to_vec(&data).map_err(|e| JsError::new(&format!("serialize error: {e}")))
    }

    pub fn from_bytes(provider: &Provider, bytes: &[u8]) -> Result<Identity, JsError> {
        let data: IdentityData = serde_json::from_slice(bytes)
            .map_err(|e| JsError::new(&format!("deserialize error: {e}")))?;

        data.keypair.store(provider.0.storage())?;

        let credential = BasicCredential::new(data.name);
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: data.keypair.public().into(),
        };

        Ok(Identity {
            credential_with_key,
            keypair: data.keypair,
        })
    }

    pub fn key_package(&self, provider: &Provider) -> KeyPackage {
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
}

#[wasm_bindgen]
pub struct AddMessages {
    proposal: Uint8Array,
    commit: Uint8Array,
    welcome: Uint8Array,
}

#[cfg(test)]
#[allow(dead_code)]
struct NativeAddMessages {
    proposal: Vec<u8>,
    commit: Vec<u8>,
    welcome: Vec<u8>,
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
pub struct RemoveMessages {
    commit: Uint8Array,
}

#[cfg(test)]
#[allow(dead_code)]
struct NativeRemoveMessages {
    commit: Vec<u8>,
}

#[wasm_bindgen]
impl RemoveMessages {
    #[wasm_bindgen(getter)]
    pub fn commit(&self) -> Uint8Array {
        self.commit.clone()
    }
}

#[wasm_bindgen]
pub struct UpdateMessages {
    commit: Uint8Array,
    welcome: Option<Uint8Array>,
}

#[cfg(test)]
#[allow(dead_code)]
struct NativeUpdateMessages {
    commit: Vec<u8>,
    welcome: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl UpdateMessages {
    #[wasm_bindgen(getter)]
    pub fn commit(&self) -> Uint8Array {
        self.commit.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn welcome(&self) -> Option<Uint8Array> {
        self.welcome.clone()
    }
}

#[wasm_bindgen]
pub struct MemberInfo {
    index: u32,
    identity: Vec<u8>,
    signature_key: Vec<u8>,
    encryption_key: Vec<u8>,
}

#[wasm_bindgen]
impl MemberInfo {
    #[wasm_bindgen(getter)]
    pub fn index(&self) -> u32 {
        self.index
    }
    #[wasm_bindgen(getter)]
    pub fn identity(&self) -> Vec<u8> {
        self.identity.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn signature_key(&self) -> Vec<u8> {
        self.signature_key.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn encryption_key(&self) -> Vec<u8> {
        self.encryption_key.clone()
    }
}

#[wasm_bindgen]
pub struct ProcessedMessage {
    msg_type: String,
    payload: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl ProcessedMessage {
    #[wasm_bindgen(getter)]
    pub fn msg_type(&self) -> String {
        self.msg_type.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn payload(&self) -> Option<Vec<u8>> {
        self.payload.clone()
    }
}

#[wasm_bindgen]
pub struct Group {
    mls_group: MlsGroup,
}

#[wasm_bindgen]
impl Group {
    pub fn create_new(provider: &Provider, founder: &Identity, group_id: &str) -> Group {
        let group_id_bytes = group_id.bytes().collect::<Vec<_>>();

        let mls_group = MlsGroup::builder()
            .ciphersuite(CIPHERSUITE)
            .max_past_epochs(MAX_PAST_EPOCHS)
            .padding_size(PADDING_SIZE)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                10,
                2000,
            ))
            .with_group_id(GroupId::from_slice(&group_id_bytes))
            .build(
                &provider.0,
                &founder.keypair,
                founder.credential_with_key.clone(),
            )
            .unwrap();

        Group { mls_group }
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
        let config = MlsGroupJoinConfig::builder()
            .max_past_epochs(MAX_PAST_EPOCHS)
            .padding_size(PADDING_SIZE)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                10,
                2000,
            ))
            .build();
        let mls_group =
            StagedWelcome::new_from_welcome(&provider.0, &config, welcome, Some(ratchet_tree.0))?
                .into_group(&provider.0)?;

        Ok(Group { mls_group })
    }

    pub fn export_ratchet_tree(&self) -> RatchetTree {
        RatchetTree(self.mls_group.export_ratchet_tree().into())
    }

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

    pub fn remove_members(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        leaf_indices: &[u32],
    ) -> Result<RemoveMessages, JsError> {
        use openmls::prelude::LeafNodeIndex;

        let indices: Vec<LeafNodeIndex> = leaf_indices
            .iter()
            .map(|&i| LeafNodeIndex::new(i))
            .collect();

        let (commit_msg, _welcome, _group_info) =
            self.mls_group
                .remove_members(provider.as_ref(), &sender.keypair, &indices)?;

        let commit = mls_message_to_uint8array(&commit_msg);

        Ok(RemoveMessages { commit })
    }

    pub fn self_update(
        &mut self,
        provider: &Provider,
        sender: &Identity,
    ) -> Result<UpdateMessages, JsError> {
        let bundle = self.mls_group.self_update(
            provider.as_ref(),
            &sender.keypair,
            LeafNodeParameters::default(),
        )?;

        let (commit_msg, welcome_msg, _group_info) = bundle.into_messages();
        let commit = mls_message_to_uint8array(&commit_msg);
        let welcome = welcome_msg.map(|w| mls_message_to_uint8array(&w));

        Ok(UpdateMessages { commit, welcome })
    }

    pub fn merge_pending_commit(&mut self, provider: &mut Provider) -> Result<(), JsError> {
        self.mls_group
            .merge_pending_commit(provider.as_mut())
            .map_err(|e| e.into())
    }

    pub fn clear_pending_commit(&mut self, provider: &Provider) -> Result<(), JsError> {
        self.mls_group
            .clear_pending_commit(provider.0.storage())
            .map_err(|e| JsError::new(&format!("clear_pending_commit error: {e}")))
    }

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

    pub fn process_message(
        &mut self,
        provider: &mut Provider,
        mut msg: &[u8],
    ) -> Result<ProcessedMessage, JsError> {
        let msg = MlsMessageIn::tls_deserialize(&mut msg)?;

        let msg = match msg.extract() {
            openmls::framing::MlsMessageBodyIn::PublicMessage(msg) => {
                self.mls_group.process_message(provider.as_ref(), msg)?
            }
            openmls::framing::MlsMessageBodyIn::PrivateMessage(msg) => {
                self.mls_group.process_message(provider.as_ref(), msg)?
            }
            openmls::framing::MlsMessageBodyIn::Welcome(_) => {
                return Err(JsError::new("unexpected Welcome message"));
            }
            openmls::framing::MlsMessageBodyIn::GroupInfo(_) => {
                return Err(JsError::new("unexpected GroupInfo message"));
            }
            openmls::framing::MlsMessageBodyIn::KeyPackage(_) => {
                return Err(JsError::new("unexpected KeyPackage message"));
            }
        };

        match msg.into_content() {
            openmls::framing::ProcessedMessageContent::ApplicationMessage(app_msg) => {
                Ok(ProcessedMessage {
                    msg_type: "application".to_string(),
                    payload: Some(app_msg.into_bytes()),
                })
            }
            openmls::framing::ProcessedMessageContent::ProposalMessage(proposal)
            | openmls::framing::ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                self.mls_group
                    .store_pending_proposal(provider.0.storage(), *proposal)?;
                Ok(ProcessedMessage {
                    msg_type: "proposal".to_string(),
                    payload: None,
                })
            }
            openmls::framing::ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                self.mls_group
                    .merge_staged_commit(provider.as_mut(), *staged_commit)?;
                Ok(ProcessedMessage {
                    msg_type: "commit".to_string(),
                    payload: None,
                })
            }
        }
    }

    pub fn members(&self) -> Vec<MemberInfo> {
        self.mls_group
            .members()
            .map(|member| MemberInfo {
                index: member.index.u32(),
                identity: member.credential.serialized_content().to_vec(),
                signature_key: member.signature_key.clone(),
                encryption_key: member.encryption_key.clone(),
            })
            .collect()
    }

    pub fn own_leaf_index(&self) -> u32 {
        self.mls_group.own_leaf_index().u32()
    }

    pub fn is_active(&self) -> bool {
        self.mls_group.is_active()
    }

    pub fn group_id(&self) -> Vec<u8> {
        self.mls_group.group_id().to_vec()
    }

    pub fn epoch(&self) -> u64 {
        self.mls_group.epoch().as_u64()
    }

    pub fn load(provider: &Provider, group_id: &str) -> Result<Group, JsError> {
        let group_id_bytes = group_id.bytes().collect::<Vec<_>>();
        let gid = GroupId::from_slice(&group_id_bytes);
        let mls_group = MlsGroup::load(provider.0.storage(), &gid)
            .map_err(|e| JsError::new(&format!("group load error: {e}")))?
            .ok_or_else(|| JsError::new("group not found in storage"))?;
        Ok(Group { mls_group })
    }

    pub fn export_key(
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
}

#[cfg(test)]
impl Group {
    fn native_propose_and_commit_add(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        new_member: &KeyPackage,
    ) -> NativeAddMessages {
        let (proposal_msg, _proposal_ref) = self
            .mls_group
            .propose_add_member(provider.as_ref(), &sender.keypair, &new_member.0)
            .unwrap();

        let (commit_msg, welcome_msg, _group_info) = self
            .mls_group
            .commit_to_pending_proposals(provider.as_ref(), &sender.keypair)
            .unwrap();

        let welcome_msg = welcome_msg.expect("expected welcome message");

        NativeAddMessages {
            proposal: mls_message_to_u8vec(&proposal_msg),
            commit: mls_message_to_u8vec(&commit_msg),
            welcome: mls_message_to_u8vec(&welcome_msg),
        }
    }

    fn native_remove_members(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        leaf_indices: &[u32],
    ) -> NativeRemoveMessages {
        use openmls::prelude::LeafNodeIndex;

        let indices: Vec<LeafNodeIndex> = leaf_indices
            .iter()
            .map(|&i| LeafNodeIndex::new(i))
            .collect();

        let (commit_msg, _welcome, _group_info) = self
            .mls_group
            .remove_members(provider.as_ref(), &sender.keypair, &indices)
            .unwrap();

        NativeRemoveMessages {
            commit: mls_message_to_u8vec(&commit_msg),
        }
    }

    fn native_self_update(
        &mut self,
        provider: &Provider,
        sender: &Identity,
    ) -> NativeUpdateMessages {
        let bundle = self
            .mls_group
            .self_update(
                provider.as_ref(),
                &sender.keypair,
                LeafNodeParameters::default(),
            )
            .unwrap();

        let (commit_msg, welcome_msg, _group_info) = bundle.into_messages();
        NativeUpdateMessages {
            commit: mls_message_to_u8vec(&commit_msg),
            welcome: welcome_msg.map(|w| mls_message_to_u8vec(&w)),
        }
    }

    fn native_join(provider: &Provider, mut welcome: &[u8], ratchet_tree: RatchetTree) -> Group {
        let welcome = match MlsMessageIn::tls_deserialize(&mut welcome)
            .unwrap()
            .extract()
        {
            MlsMessageBodyIn::Welcome(w) => w,
            other => panic!("expected a message of type welcome, got {other:?}"),
        };
        let config = MlsGroupJoinConfig::builder()
            .max_past_epochs(MAX_PAST_EPOCHS)
            .build();
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

    fn native_process_message(
        &mut self,
        provider: &mut Provider,
        msg: &[u8],
    ) -> (String, Option<Vec<u8>>) {
        let mut reader = msg;
        let msg = MlsMessageIn::tls_deserialize(&mut reader).unwrap();

        let processed = match msg.extract() {
            openmls::framing::MlsMessageBodyIn::PublicMessage(msg) => self
                .mls_group
                .process_message(provider.as_ref(), msg)
                .unwrap(),
            openmls::framing::MlsMessageBodyIn::PrivateMessage(msg) => self
                .mls_group
                .process_message(provider.as_ref(), msg)
                .unwrap(),
            _ => panic!("unexpected message type"),
        };

        match processed.into_content() {
            openmls::framing::ProcessedMessageContent::ApplicationMessage(app_msg) => {
                ("application".to_string(), Some(app_msg.into_bytes()))
            }
            openmls::framing::ProcessedMessageContent::ProposalMessage(proposal)
            | openmls::framing::ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                self.mls_group
                    .store_pending_proposal(provider.0.storage(), *proposal)
                    .unwrap();
                ("proposal".to_string(), None)
            }
            openmls::framing::ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                self.mls_group
                    .merge_staged_commit(provider.as_mut(), *staged_commit)
                    .unwrap();
                ("commit".to_string(), None)
            }
        }
    }

    fn native_merge_pending_commit(&mut self, provider: &mut Provider) {
        self.mls_group
            .merge_pending_commit(provider.as_mut())
            .unwrap();
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
    #[wasm_bindgen]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.tls_serialize_detached().unwrap()
    }

    #[wasm_bindgen]
    pub fn from_bytes(bytes: &[u8]) -> Result<KeyPackage, JsError> {
        let mut s = bytes;
        let kp_in = openmls::key_packages::KeyPackageIn::tls_deserialize(&mut s)
            .map_err(|e| JsError::new(&format!("KeyPackage deserialization error: {e}")))?;
        let kp = kp_in
            .validate(
                &openmls_rust_crypto::RustCrypto::default(),
                openmls::prelude::ProtocolVersion::Mls10,
            )
            .map_err(|e| JsError::new(&format!("KeyPackage validation error: {e}")))?;
        Ok(KeyPackage(kp))
    }
}

#[wasm_bindgen]
pub struct RatchetTree(RatchetTreeIn);

#[wasm_bindgen]
impl RatchetTree {
    #[wasm_bindgen]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.tls_serialize_detached().unwrap()
    }

    #[wasm_bindgen]
    pub fn from_bytes(bytes: &[u8]) -> Result<RatchetTree, JsError> {
        let mut s = bytes;
        let tree = RatchetTreeIn::tls_deserialize(&mut s)
            .map_err(|e| JsError::new(&format!("RatchetTree deserialization error: {e}")))?;
        Ok(RatchetTree(tree))
    }
}

fn mls_message_to_uint8array(msg: &MlsMessageOut) -> Uint8Array {
    let mut serialized = vec![];
    msg.tls_serialize(&mut serialized).unwrap();
    unsafe { Uint8Array::new(&Uint8Array::view(&serialized)) }
}

#[cfg(test)]
fn mls_message_to_u8vec(msg: &MlsMessageOut) -> Vec<u8> {
    let mut serialized = vec![];
    msg.tls_serialize(&mut serialized).unwrap();
    serialized
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_group_alice_and_bob() -> (Provider, Identity, Group, Provider, Identity, Group) {
        let alice_provider = Provider::new();
        let bob_provider = Provider::new();

        let alice = Identity::new(&alice_provider, "alice").unwrap();
        let bob = Identity::new(&bob_provider, "bob").unwrap();

        let mut chess_club_alice = Group::create_new(&alice_provider, &alice, "chess club");

        let bob_key_pkg = bob.key_package(&bob_provider);

        let add_msgs =
            chess_club_alice.native_propose_and_commit_add(&alice_provider, &alice, &bob_key_pkg);

        let mut alice_prov = alice_provider;
        chess_club_alice.native_merge_pending_commit(&mut alice_prov);

        let ratchet_tree = chess_club_alice.export_ratchet_tree();
        let chess_club_bob = Group::native_join(&bob_provider, &add_msgs.welcome, ratchet_tree);

        (
            alice_prov,
            alice,
            chess_club_alice,
            bob_provider,
            bob,
            chess_club_bob,
        )
    }

    fn create_group_alice_bob_charlie() -> (
        Provider,
        Identity,
        Group,
        Provider,
        Identity,
        Group,
        Provider,
        Identity,
        Group,
    ) {
        let (
            mut alice_provider,
            alice,
            mut chess_club_alice,
            bob_provider,
            bob,
            mut chess_club_bob,
        ) = create_group_alice_and_bob();

        let charlie_provider = Provider::new();
        let charlie = Identity::new(&charlie_provider, "charlie").unwrap();
        let charlie_key_pkg = charlie.key_package(&charlie_provider);

        let add_msgs = chess_club_alice
            .native_propose_and_commit_add(&alice_provider, &alice, &charlie_key_pkg);

        chess_club_alice.native_merge_pending_commit(&mut alice_provider);

        let mut bob_prov = bob_provider;
        chess_club_bob.native_process_message(&mut bob_prov, &add_msgs.proposal);
        chess_club_bob.native_process_message(&mut bob_prov, &add_msgs.commit);

        let ratchet_tree = chess_club_alice.export_ratchet_tree();
        let chess_club_charlie =
            Group::native_join(&charlie_provider, &add_msgs.welcome, ratchet_tree);

        (
            alice_provider,
            alice,
            chess_club_alice,
            bob_prov,
            bob,
            chess_club_bob,
            charlie_provider,
            charlie,
            chess_club_charlie,
        )
    }

    #[test]
    fn basic() {
        let (alice_provider, _, chess_club_alice, bob_provider, _, chess_club_bob) =
            create_group_alice_and_bob();

        let bob_exported_key = chess_club_bob
            .export_key(&bob_provider, "chess_key", &[0x30], 32)
            .unwrap();
        let alice_exported_key = chess_club_alice
            .export_key(&alice_provider, "chess_key", &[0x30], 32)
            .unwrap();

        assert_eq!(bob_exported_key, alice_exported_key);
    }

    #[test]
    fn create_message() {
        let (alice_provider, alice, mut chess_club_alice, mut bob_provider, _, mut chess_club_bob) =
            create_group_alice_and_bob();

        let alice_msg = "hello, bob!".as_bytes();
        let msg_out = chess_club_alice
            .create_message(&alice_provider, &alice, alice_msg)
            .unwrap();

        let (msg_type, payload) =
            chess_club_bob.native_process_message(&mut bob_provider, &msg_out);

        assert_eq!(msg_type, "application");
        assert_eq!(payload.unwrap(), alice_msg);
    }

    #[test]
    fn identity_serialize_roundtrip() {
        let provider = Provider::new();
        let alice = Identity::new(&provider, "alice").unwrap();

        let bytes = alice.to_bytes().unwrap();
        assert!(!bytes.is_empty());

        let provider2 = Provider::new();
        let restored = Identity::from_bytes(&provider2, &bytes).unwrap();

        assert_eq!(
            alice.credential_with_key.signature_key,
            restored.credential_with_key.signature_key
        );
        assert_eq!(
            alice.credential_with_key.credential.serialized_content(),
            restored.credential_with_key.credential.serialized_content()
        );
    }

    #[test]
    fn members_and_own_leaf_index() {
        let (_, _, chess_club_alice, _, _, chess_club_bob) = create_group_alice_and_bob();

        let alice_members = chess_club_alice.members();
        assert_eq!(alice_members.len(), 2);

        let bob_members = chess_club_bob.members();
        assert_eq!(bob_members.len(), 2);

        assert_eq!(chess_club_alice.own_leaf_index(), 0);
        assert_eq!(chess_club_bob.own_leaf_index(), 1);

        assert_eq!(alice_members[0].identity, b"alice");
        assert_eq!(alice_members[1].identity, b"bob");
    }

    #[test]
    fn group_id_and_is_active() {
        let (_, _, chess_club_alice, _, _, chess_club_bob) = create_group_alice_and_bob();

        assert!(chess_club_alice.is_active());
        assert!(chess_club_bob.is_active());

        assert_eq!(chess_club_alice.group_id(), b"chess club");
        assert_eq!(chess_club_bob.group_id(), b"chess club");
    }

    #[test]
    fn remove_member() {
        let (
            mut alice_provider,
            alice,
            mut chess_club_alice,
            _bob_provider,
            _bob,
            chess_club_bob,
            mut charlie_provider,
            _charlie,
            mut chess_club_charlie,
        ) = create_group_alice_bob_charlie();

        assert_eq!(chess_club_alice.members().len(), 3);

        let bob_leaf = chess_club_bob.own_leaf_index();
        let remove_msgs =
            chess_club_alice.native_remove_members(&alice_provider, &alice, &[bob_leaf]);

        chess_club_alice.native_merge_pending_commit(&mut alice_provider);

        chess_club_charlie.native_process_message(&mut charlie_provider, &remove_msgs.commit);

        assert_eq!(chess_club_alice.members().len(), 2);
        assert_eq!(chess_club_charlie.members().len(), 2);
    }

    #[test]
    fn self_update() {
        let (
            mut alice_provider,
            alice,
            mut chess_club_alice,
            mut bob_provider,
            _bob,
            mut chess_club_bob,
        ) = create_group_alice_and_bob();

        let update_msgs = chess_club_alice.native_self_update(&alice_provider, &alice);

        chess_club_alice.native_merge_pending_commit(&mut alice_provider);

        let (msg_type, _payload) =
            chess_club_bob.native_process_message(&mut bob_provider, &update_msgs.commit);

        assert_eq!(msg_type, "commit");

        assert!(chess_club_alice.is_active());
        assert!(chess_club_bob.is_active());

        let alice_key = chess_club_alice
            .export_key(&alice_provider, "test", &[0x01], 32)
            .unwrap();
        let bob_key = chess_club_bob
            .export_key(&bob_provider, "test", &[0x01], 32)
            .unwrap();
        assert_eq!(alice_key, bob_key);
    }

    #[test]
    fn provider_and_group_persistence_roundtrip() {
        let (alice_provider, alice, mut chess_club_alice, mut bob_provider, _, mut chess_club_bob) =
            create_group_alice_and_bob();

        let msg_bytes = chess_club_alice
            .create_message(&alice_provider, &alice, b"before serialize")
            .unwrap();
        chess_club_bob.native_process_message(&mut bob_provider, &msg_bytes);

        let epoch_before = chess_club_alice.epoch();

        let provider_bytes = alice_provider.to_bytes().unwrap();
        assert!(!provider_bytes.is_empty());

        let alice_bytes = alice.to_bytes().unwrap();

        let alice_provider2 = Provider::from_bytes(&provider_bytes).unwrap();

        let alice2 = Identity::from_bytes(&alice_provider2, &alice_bytes).unwrap();

        let mut restored_group = Group::load(&alice_provider2, "chess club").unwrap();

        assert_eq!(restored_group.epoch(), epoch_before);
        assert!(restored_group.is_active());
        assert_eq!(restored_group.group_id(), b"chess club");
        assert_eq!(restored_group.members().len(), 2);

        let msg_bytes2 = restored_group
            .create_message(&alice_provider2, &alice2, b"after restore")
            .unwrap();

        let (msg_type, payload) =
            chess_club_bob.native_process_message(&mut bob_provider, &msg_bytes2);
        assert_eq!(msg_type, "application");
        assert_eq!(payload.unwrap(), b"after restore");
    }

    #[test]
    fn process_message_returns_structured_type() {
        let (alice_provider, alice, mut chess_club_alice, mut bob_provider, _, mut chess_club_bob) =
            create_group_alice_and_bob();

        let msg_bytes = chess_club_alice
            .create_message(&alice_provider, &alice, b"structured test")
            .unwrap();

        let (msg_type, payload) =
            chess_club_bob.native_process_message(&mut bob_provider, &msg_bytes);

        assert_eq!(msg_type, "application");
        assert_eq!(payload.unwrap(), b"structured test");
    }
}
