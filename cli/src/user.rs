use std::borrow::Borrow;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;
use std::{cell::RefCell, collections::HashMap, str};

use ds_lib::{ClientKeyPackages, GroupMessage};
use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;
use tls_codec::TlsByteVecU8;

use super::{
    backend::Backend, conversation::Conversation, conversation::ConversationMessage, file_helpers,
    identity::Identity, openmls_rust_persistent_crypto::OpenMlsRustPersistentCrypto,
    serialize_any_hashmap,
};

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Contact {
    username: String,
    id: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Group {
    group_name: String,
    conversation: Conversation,
    mls_group: RefCell<MlsGroup>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct User {
    pub(crate) username: String,
    #[serde(
        serialize_with = "serialize_any_hashmap::serialize_hashmap",
        deserialize_with = "serialize_any_hashmap::deserialize_hashmap"
    )]
    pub(crate) contacts: HashMap<Vec<u8>, Contact>,
    #[serde(skip)]
    pub(crate) groups: RefCell<HashMap<String, Group>>,
    group_list: HashSet<String>,
    pub(crate) identity: RefCell<Identity>,
    #[serde(skip)]
    backend: Backend,
    #[serde(skip)]
    crypto: OpenMlsRustPersistentCrypto,
    autosave_enabled: bool,
}

#[derive(PartialEq)]
pub enum PostUpdateActions {
    None,
    Remove,
}

impl User {
    /// Create a new user with the given name and a fresh set of credentials.
    pub fn new(username: String) -> Self {
        let crypto = OpenMlsRustPersistentCrypto::default();
        let out = Self {
            username: username.clone(),
            groups: RefCell::new(HashMap::new()),
            group_list: HashSet::new(),
            contacts: HashMap::new(),
            identity: RefCell::new(Identity::new(CIPHERSUITE, &crypto, username.as_bytes())),
            backend: Backend::default(),
            crypto,
            autosave_enabled: false,
        };
        out
    }

    fn get_file_path(user_name: &String) -> PathBuf {
        file_helpers::get_file_path(&("openmls_cli_".to_owned() + user_name + ".json"))
    }

    fn load_from_file(input_file: &File) -> Result<Self, String> {
        // Prepare file reader.
        let reader = BufReader::new(input_file);

        // Read the JSON contents of the file as an instance of `User`.
        match serde_json::from_reader::<BufReader<&File>, User>(reader) {
            Ok(user) => return Ok(user),
            Err(e) => return Result::Err(e.to_string()),
        }
    }

    pub fn load(user_name: String) -> Result<Self, String> {
        let input_path = User::get_file_path(&user_name);

        match File::open(input_path) {
            Err(e) => {
                log::error!("Error loading user state: {:?}", e.to_string());
                return Err(e.to_string());
            }
            Ok(input_file) => {
                let user_result = User::load_from_file(&input_file);

                if user_result.is_ok() {
                    let mut user = user_result.ok().unwrap();
                    match user.crypto.load_keystore(user_name) {
                        Ok(_) => {
                            let groups = user.groups.get_mut();
                            for group_name in &user.group_list {
                                let mlsgroup = MlsGroup::load(
                                    &GroupId::from_slice(group_name.as_bytes()),
                                    user.crypto.key_store(),
                                );
                                let grp = Group {
                                    mls_group: RefCell::new(mlsgroup.unwrap()),
                                    group_name: group_name.clone(),
                                    conversation: Conversation::default(),
                                };
                                groups.insert(group_name.clone(), grp);
                            }
                            return Ok(user);
                        }
                        Err(e) => Err(e),
                    }
                } else {
                    return user_result;
                }
            }
        }
    }

    fn save_to_file(&self, output_file: &File) {
        let writer = BufWriter::new(output_file);
        match serde_json::to_writer_pretty(writer, &self) {
            Ok(()) => log::info!("User serialized"),
            Err(e) => log::error!("Error serializing user: {:?}", e.to_string()),
        }
    }

    pub fn save(&mut self) {
        let output_path = User::get_file_path(&self.username);
        match File::create(output_path) {
            Err(e) => log::error!("Error saving user state: {:?}", e.to_string()),
            Ok(output_file) => {
                let groups = self.groups.get_mut();
                for (group_name, group) in groups {
                    self.group_list.replace(group_name.clone());
                    group
                        .mls_group
                        .borrow_mut()
                        .save(self.crypto.key_store())
                        .unwrap();
                }

                self.save_to_file(&output_file);

                match self.crypto.save_keystore(self.username.clone()) {
                    Ok(_) => log::info!("User state saved"),
                    Err(e) => log::error!("Error saving user state : {:?}", e.to_string()),
                }
            }
        }
    }

    pub fn enable_auto_save(&mut self) {
        self.autosave_enabled = true;
    }

    fn autosave(&mut self) {
        if self.autosave_enabled {
            self.save();
        }
    }

    /// Add a key package to the user identity and return the pair [key package hash ref , key package]
    pub fn add_key_package(&self) -> (Vec<u8>, KeyPackage) {
        let kp = self
            .identity
            .borrow_mut()
            .add_key_package(CIPHERSUITE, &self.crypto);
        (
            kp.hash_ref(self.crypto.crypto())
                .unwrap()
                .as_slice()
                .to_vec(),
            kp,
        )
    }

    /// Get a member
    fn find_member_index(&self, name: String, group: &Group) -> Result<LeafNodeIndex, String> {
        let mls_group = group.mls_group.borrow();
        for Member {
            index,
            encryption_key: _,
            signature_key: _,
            credential,
        } in mls_group.members()
        {
            if credential.identity() == name.as_bytes() {
                return Ok(index);
            }
        }
        Err("Unknown member".to_string())
    }

    /// Get the key packages fo this user.
    pub fn key_packages(&self) -> Vec<(Vec<u8>, KeyPackage)> {
        // clone first !
        let kpgs = self.identity.borrow().kp.clone();
        Vec::from_iter(kpgs)
    }

    pub fn register(&self) {
        match self.backend.register_client(self) {
            Ok(r) => log::debug!("Created new user: {:?}", r),
            Err(e) => log::error!("Error creating user: {:?}", e),
        }
    }

    /// Get a list of clients in the group to send messages to.
    fn recipients(&self, group: &Group) -> Vec<Vec<u8>> {
        let mut recipients = Vec::new();

        let mls_group = group.mls_group.borrow();
        for Member {
            index: _,
            encryption_key: _,
            signature_key,
            credential,
        } in mls_group.members()
        {
            if self
                .identity
                .borrow()
                .credential_with_key
                .signature_key
                .as_slice()
                != signature_key.as_slice()
            {
                log::debug!(
                    "Searching for contact {:?}",
                    str::from_utf8(credential.identity()).unwrap()
                );
                let contact = match self.contacts.get(&credential.identity().to_vec()) {
                    Some(c) => c.id.clone(),
                    None => panic!("There's a member in the group we don't know."),
                };
                recipients.push(contact);
            }
        }
        recipients
    }

    /// Return the last 100 messages sent to the group.
    pub fn read_msgs(
        &self,
        group_name: String,
    ) -> Result<Option<Vec<ConversationMessage>>, String> {
        let groups = self.groups.borrow();
        groups.get(&group_name).map_or_else(
            || Err("Unknown group".to_string()),
            |g| {
                Ok(g.conversation
                    .get(100)
                    .map(|messages: &[crate::conversation::ConversationMessage]| messages.to_vec()))
            },
        )
    }

    /// Create a new key package and publish it to the delivery server
    pub fn create_kp(&self) {
        let kp = self.add_key_package();
        let ckp = ClientKeyPackages(
            vec![kp]
                .into_iter()
                .map(|(b, kp)| (b.into(), KeyPackageIn::from(kp)))
                .collect::<Vec<(TlsByteVecU8, KeyPackageIn)>>()
                .into(),
        );

        match self.backend.publish_key_packages(self, &ckp) {
            Ok(()) => (),
            Err(e) => println!("Error sending new key package: {e:?}"),
        };
    }

    /// Send an application message to the group.
    pub fn send_msg(&self, msg: &str, group: String) -> Result<(), String> {
        let groups = self.groups.borrow();
        let group = match groups.get(&group) {
            Some(g) => g,
            None => return Err("Unknown group".to_string()),
        };

        let message_out = group
            .mls_group
            .borrow_mut()
            .create_message(&self.crypto, &self.identity.borrow().signer, msg.as_bytes())
            .map_err(|e| format!("{e}"))?;

        let msg = GroupMessage::new(message_out.into(), &self.recipients(group));
        log::debug!(" >>> send: {:?}", msg);
        match self.backend.send_msg(&msg) {
            Ok(()) => (),
            Err(e) => println!("Error sending group message: {e:?}"),
        }

        // XXX: Need to update the client's local view of the conversation to include
        // the message they sent.

        Ok(())
    }

    /// Update the user. This involves:
    /// * retrieving all new messages from the server
    /// * update the contacts with all other clients known to the server
    pub fn update(
        &mut self,
        group_name: Option<String>,
    ) -> Result<Vec<ConversationMessage>, String> {
        log::debug!("Updating {} ...", self.username);

        let mut messages_out: Vec<ConversationMessage> = Vec::new();

        let mut process_protocol_message = |message: ProtocolMessage| -> Result<
            (PostUpdateActions, Option<GroupId>),
            String,
        > {
            let processed_message: ProcessedMessage;
            let mut groups = self.groups.borrow_mut();

            let group = match groups.get_mut(str::from_utf8(message.group_id().as_slice()).unwrap())
            {
                Some(g) => g,
                None => {
                    log::error!(
                        "Error getting group {:?} for a message. Dropping message.",
                        message.group_id()
                    );
                    return Err("error".to_string());
                }
            };
            let mut mls_group = group.mls_group.borrow_mut();

            processed_message = match mls_group.process_message(&self.crypto, message) {
                Ok(msg) => msg,
                Err(e) => {
                    log::error!(
                        "Error processing unverified message: {:?} -  Dropping message.",
                        e
                    );
                    return Err("error".to_string());
                }
            };

            let processed_message_credential: Credential = processed_message.credential().clone();

            match processed_message.into_content() {
                ProcessedMessageContent::ApplicationMessage(application_message) => {
                    let sender_name =
                        match self.contacts.get(processed_message_credential.identity()) {
                            Some(c) => &c.username,
                            None => panic!("There's a member in the group we don't know."),
                        };
                    let conversation_message = ConversationMessage::new(
                        String::from_utf8(application_message.into_bytes())
                            .unwrap()
                            .clone(),
                        sender_name.to_string(),
                    );
                    if group_name.is_none() || group_name.clone().unwrap() == group.group_name {
                        messages_out.push(conversation_message.clone());
                    }
                    group.conversation.add(conversation_message);
                }
                ProcessedMessageContent::ProposalMessage(_proposal_ptr) => {
                    // intentionally left blank.
                }
                ProcessedMessageContent::ExternalJoinProposalMessage(_external_proposal_ptr) => {
                    // intentionally left blank.
                }
                ProcessedMessageContent::StagedCommitMessage(commit_ptr) => {
                    let mut remove_proposal: bool = false;
                    if commit_ptr.self_removed() {
                        remove_proposal = true;
                    }
                    match mls_group.merge_staged_commit(&self.crypto, *commit_ptr) {
                        Ok(()) => {
                            if remove_proposal {
                                log::debug!("update::Processing StagedCommitMessage removing {} from group {} ", self.username, group.group_name);
                                return Ok((
                                    PostUpdateActions::Remove,
                                    Some(mls_group.group_id().clone()),
                                ));
                            }
                        }
                        Err(e) => return Err(e.to_string()),
                    }
                }
            }
            Ok((PostUpdateActions::None, None))
        };

        log::debug!("update::Processing messages for {} ", self.username);
        // Go through the list of messages and process or store them.
        for message in self.backend.recv_msgs(self)?.drain(..) {
            log::debug!("Reading message format {:#?} ...", message.wire_format());
            match message.extract() {
                MlsMessageInBody::Welcome(welcome) => {
                    // Join the group. (Later we should ask the user to
                    // approve first ...)
                    self.join_group(welcome)?;
                }
                MlsMessageInBody::PrivateMessage(message) => {
                    match process_protocol_message(message.into()) {
                        Ok(p) => {
                            if p.0 == PostUpdateActions::Remove {
                                match p.1 {
                                    Some(gid) => {
                                        let mut grps = self.groups.borrow_mut();
                                        grps.remove_entry(str::from_utf8(gid.as_slice()).unwrap());
                                        self.group_list
                                            .remove(str::from_utf8(gid.as_slice()).unwrap());
                                    }
                                    None => log::debug!(
                                        "update::Error post update remove must have a group id"
                                    ),
                                }
                            }
                        }
                        Err(_e) => {
                            continue;
                        }
                    };
                }
                MlsMessageInBody::PublicMessage(message) => {
                    if process_protocol_message(message.into()).is_err() {
                        continue;
                    }
                }
                _ => panic!("Unsupported message type"),
            }
        }
        log::debug!("update::Processing messages done");

        for c in self.backend.list_clients()?.drain(..) {
            let client_id = c.id.clone();
            log::debug!(
                "update::Processing client for contact {:?}",
                str::from_utf8(&client_id).unwrap()
            );
            if c.id != self.identity.borrow().identity()
                && self
                    .contacts
                    .insert(
                        c.id.clone(),
                        Contact {
                            username: c.client_name,
                            id: c.id,
                        },
                    )
                    .is_some()
            {
                log::debug!(
                    "update::added client to contact {:?}",
                    str::from_utf8(&client_id).unwrap()
                );
                log::trace!("Updated client {}", "");
            }
        }
        log::debug!("update::Processing clients done, contact list is:");
        for contact_id in self.contacts.borrow().keys() {
            log::debug!(
                "update::Parsing contact {:?}",
                str::from_utf8(contact_id).unwrap()
            );
        }

        self.autosave();

        Ok(messages_out)
    }

    /// Create a group with the given name.
    pub fn create_group(&mut self, name: String) {
        log::debug!("{} creates group {}", self.username, name);
        let group_id = name.as_bytes();
        let mut group_aad = group_id.to_vec();
        group_aad.extend(b" AAD");

        // NOTE: Since the DS currently doesn't distribute copies of the group's ratchet
        // tree, we need to include the ratchet_tree_extension.
        let group_config = MlsGroupConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();

        let mut mls_group = MlsGroup::new_with_group_id(
            &self.crypto,
            &self.identity.borrow().signer,
            &group_config,
            GroupId::from_slice(group_id),
            self.identity.borrow().credential_with_key.clone(),
        )
        .expect("Failed to create MlsGroup");
        mls_group.set_aad(group_aad.as_slice());

        let group = Group {
            group_name: name.clone(),
            conversation: Conversation::default(),
            mls_group: RefCell::new(mls_group),
        };

        if self.groups.borrow().contains_key(&name) {
            panic!("Group '{}' existed already", name);
        }

        self.groups.borrow_mut().insert(name, group);

        self.autosave();
    }

    /// Invite user with the given name to the group.
    pub fn invite(&mut self, name: String, group_name: String) -> Result<(), String> {
        // First we need to get the key package for {id} from the DS.
        let contact = match self.contacts.values().find(|c| c.username == name) {
            Some(v) => v,
            None => return Err(format!("No contact with name {name} known.")),
        };

        // Reclaim a key package from the server
        let joiner_key_package = self.backend.consume_key_package(&contact.id).unwrap();

        // Build a proposal with this key package and do the MLS bits.
        let mut groups = self.groups.borrow_mut();
        let group = match groups.get_mut(&group_name) {
            Some(g) => g,
            None => return Err(format!("No group with name {group_name} known.")),
        };

        let (out_messages, welcome, _group_info) = group
            .mls_group
            .borrow_mut()
            .add_members(
                &self.crypto,
                &self.identity.borrow().signer,
                &[joiner_key_package.into()],
            )
            .map_err(|e| format!("Failed to add member to group - {e}"))?;

        /* First, send the MlsMessage commit to the group.
        This must be done before the member invitation is locally committed.
        It avoids the invited member to receive the commit message (which is in the previous group epoch).*/
        log::trace!("Sending commit");
        let group = groups.get_mut(&group_name).unwrap(); // XXX: not cool.
        let group_recipients = self.recipients(group);

        let msg = GroupMessage::new(out_messages.into(), &group_recipients);
        self.backend.send_msg(&msg)?;

        // Second, process the invitation on our end.
        group
            .mls_group
            .borrow_mut()
            .merge_pending_commit(&self.crypto)
            .expect("error merging pending commit");

        // Finally, send Welcome to the joiner.
        log::trace!("Sending welcome");
        self.backend
            .send_welcome(&welcome)
            .expect("Error sending Welcome message");

        drop(groups);

        self.autosave();

        Ok(())
    }

    /// Remove user with the given name from the group.
    pub fn remove(&mut self, name: String, group_name: String) -> Result<(), String> {
        // Get the group ID

        let mut groups = self.groups.borrow_mut();
        let group = match groups.get_mut(&group_name) {
            Some(g) => g,
            None => return Err(format!("No group with name {group_name} known.")),
        };

        // Get the client leaf index

        let leaf_index = match self.find_member_index(name, group) {
            Ok(l) => l,
            Err(e) => return Err(e),
        };

        // Remove operation on the mls group
        let (remove_message, _welcome, _group_info) = group
            .mls_group
            .borrow_mut()
            .remove_members(&self.crypto, &self.identity.borrow().signer, &[leaf_index])
            .map_err(|e| format!("Failed to add member to group - {e}"))?;

        // First, send the MlsMessage remove commit to the group.
        log::trace!("Sending commit");
        let group = groups.get_mut(&group_name).unwrap(); // XXX: not cool.
        let group_recipients = self.recipients(group);

        let msg = GroupMessage::new(remove_message.into(), &group_recipients);
        self.backend.send_msg(&msg)?;

        // Second, process the removal on our end.
        group
            .mls_group
            .borrow_mut()
            .merge_pending_commit(&self.crypto)
            .expect("error merging pending commit");

        drop(groups);

        self.autosave();

        Ok(())
    }

    /// Join a group with the provided welcome message.
    fn join_group(&self, welcome: Welcome) -> Result<(), String> {
        log::debug!("{} joining group ...", self.username);

        let mut ident = self.identity.borrow_mut();
        for secret in welcome.secrets().iter() {
            let key_package_hash = &secret.new_member();
            if ident.kp.contains_key(key_package_hash.as_slice()) {
                ident.kp.remove(key_package_hash.as_slice());
            }
        }
        // NOTE: Since the DS currently doesn't distribute copies of the group's ratchet
        // tree, we need to include the ratchet_tree_extension.
        let group_config = MlsGroupConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let mut mls_group = MlsGroup::new_from_welcome(&self.crypto, &group_config, welcome, None)
            .expect("Failed to create MlsGroup");

        let group_id = mls_group.group_id().to_vec();
        // XXX: Use Welcome's encrypted_group_info field to store group_name.
        let group_name = String::from_utf8(group_id.clone()).unwrap();
        let group_aad = group_name.clone() + " AAD";

        mls_group.set_aad(group_aad.as_bytes());

        let group = Group {
            group_name: group_name.clone(),
            conversation: Conversation::default(),
            mls_group: RefCell::new(mls_group),
        };

        log::trace!("   {}", group_name);

        match self.groups.borrow_mut().insert(group_name, group) {
            Some(old) => Err(format!("Overrode the group {:?}", old.group_name)),
            None => Ok(()),
        }
    }
}
