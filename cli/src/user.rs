use std::{cell::RefCell, collections::HashMap};

use ds_lib::{ClientKeyPackages, DsMlsMessage, GroupMessage, Message};
use openmls::{group::create_commit_params::CreateCommitParams, prelude::*};
use openmls_rust_crypto::OpenMlsRustCrypto;

use super::{backend::Backend, conversation::Conversation, identity::Identity};

const CIPHERSUITE: CiphersuiteName =
    CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const PADDING_SIZE: usize = 0;

pub struct Contact {
    username: String,
    id: Vec<u8>,
    // We store multiple here but always only use the first one right now.
    #[allow(dead_code)]
    public_keys: ClientKeyPackages,
}

pub struct Group {
    #[allow(dead_code)]
    group_id: Vec<u8>,
    group_name: String,
    group_aad: Vec<u8>,
    members: Vec<Vec<u8>>,
    conversation: Conversation,
    mls_group: RefCell<MlsGroup>,
    pending_proposals: Vec<MlsPlaintext>,
}

pub struct User {
    pub(crate) username: String,
    pub(crate) contacts: HashMap<Vec<u8>, Contact>,
    pub(crate) groups: RefCell<HashMap<Vec<u8>, Group>>,
    pub(crate) identity: RefCell<Identity>,
    backend: Backend,
    crypto: OpenMlsRustCrypto,
}

impl User {
    /// Create a new user with the given name and a fresh set of credentials.
    pub fn new(username: String) -> Self {
        let crypto = OpenMlsRustCrypto::default();
        let out = Self {
            username: username.clone(),
            groups: RefCell::new(HashMap::new()),
            contacts: HashMap::new(),
            identity: RefCell::new(Identity::new(CIPHERSUITE, &crypto, username.as_bytes())),
            backend: Backend::default(),
            crypto,
        };

        match out.backend.register_client(&out) {
            Ok(r) => log::debug!("Created new user: {:?}", r),
            Err(e) => log::error!("Error creating user: {:?}", e),
        }

        out
    }

    /// Get the key packages fo this user.
    pub fn key_packages(&self) -> Vec<(Vec<u8>, KeyPackage)> {
        vec![(
            self.identity.borrow().kpb.key_package().hash(&self.crypto),
            self.identity.borrow().kpb.key_package().clone(),
        )]
    }

    /// Get a list of clients in the group to send messages to.
    fn recipients(&self, group: &Group) -> Vec<Vec<u8>> {
        let mut recipients = Vec::new();
        for member in group.members.iter() {
            if self.identity.borrow().credential.credential().identity() != member {
                let contact = match self.contacts.get(member) {
                    Some(c) => c.id.clone(),
                    None => panic!("There's a member in the group we don't know."),
                };
                recipients.push(contact);
            }
        }
        recipients
    }

    /// Send an application message to the group.
    pub fn send_msg(&self, msg: &str, group: String) -> Result<(), String> {
        let groups = self.groups.borrow();
        let group = match groups.get(group.as_bytes()) {
            Some(g) => g,
            None => return Err("Unknown group".to_string()),
        };

        let mls_ciphertext = match group.mls_group.borrow_mut().create_application_message(
            &group.group_aad,
            msg.as_bytes(),
            &self.identity.borrow().credential,
            PADDING_SIZE,
            &self.crypto,
        ) {
            Ok(m) => m,
            Err(e) => return Err(format!("{}", e)),
        };

        // Send mls_ciphertext to the group
        let msg = GroupMessage::new(
            DsMlsMessage::Ciphertext(mls_ciphertext),
            &self.recipients(group),
        );
        log::debug!(" >>> send: {:?}", msg);
        let _response = self.backend.send_msg(&msg)?;
        Ok(())
    }

    /// Update the user. This involves:
    /// * retrieving all new messages from the server
    /// * update the contacts with all other clients known to the server
    pub fn update(&mut self, group_name: Option<String>) -> Result<Vec<String>, String> {
        log::debug!("Updating {} ...", self.username);

        let mut messages_out = Vec::new();

        // Go through the list of messages and process or store them.
        for message in self.backend.recv_msgs(self)?.drain(..) {
            match message {
                Message::Welcome(welcome) => {
                    // Join the group. (Later we should ask the user to
                    // approve first ...)
                    self.join_group(welcome)?;
                }
                Message::MlsMessage(message) => {
                    let mut groups = self.groups.borrow_mut();
                    let mut group = match groups.get(message.group_id()) {
                        Some(g) => g.mls_group.borrow_mut(),
                        None => {
                            log::error!(
                                "Error getting group {:?} for a message. Dropping message.",
                                message.group_id()
                            );
                            continue;
                        }
                    };
                    let msg = match message {
                        DsMlsMessage::Ciphertext(ctxt) => {
                            let verifiable_plaintext = match group.decrypt(&ctxt, &self.crypto) {
                                Ok(msg) => msg,
                                Err(e) => {
                                    log::error!(
                                        "Error decrypting MlsCiphertext: {:?} -  Dropping message.",
                                        e
                                    );
                                    continue;
                                }
                            };
                            match group.verify(verifiable_plaintext, &self.crypto) {
                                Ok(msg) => msg,
                                Err(e) => {
                                    log::error!(
                                        "Error verifying MlsPlaintext: {:?} -  Dropping message.",
                                        e
                                    );
                                    continue;
                                }
                            }
                        }
                        DsMlsMessage::Plaintext(msg) => match group.verify(msg, &self.crypto) {
                            Ok(msg) => msg,
                            Err(e) => {
                                log::error!(
                                    "Error verifying MlsPlaintext: {:?} -  Dropping message.",
                                    e
                                );
                                continue;
                            }
                        },
                    };
                    drop(group);
                    let group = match groups.get_mut(&msg.group_id().to_vec()) {
                        Some(g) => g,
                        None => {
                            log::error!(
                                "Error getting group {:?} for a message. Dropping message.",
                                msg.group_id().as_slice()
                            );
                            continue;
                        }
                    };
                    match msg.content() {
                        MlsPlaintextContentType::Application(application_message) => {
                            let application_message =
                                String::from_utf8(application_message.as_slice().to_vec()).unwrap();
                            if group_name.is_none()
                                || group_name.clone().unwrap() == group.group_name
                            {
                                messages_out.push(application_message.clone());
                            }
                            group.conversation.add(application_message);
                        }
                        MlsPlaintextContentType::Proposal(_proposal) => {
                            // Store the proposal to use later when we got a
                            // corresponding commit.
                            group.pending_proposals.push(msg);
                        }
                        MlsPlaintextContentType::Commit(_commit) => {
                            let mut proposal_store = ProposalStore::new();
                            for proposal in &group.pending_proposals {
                                proposal_store.add(
                                    StagedProposal::from_mls_plaintext(
                                        Config::ciphersuite(CIPHERSUITE)
                                            .map_err(|e| format!("{}", e))?,
                                        &self.crypto,
                                        proposal.clone(),
                                    )
                                    .map_err(|e| format!("{}", e))?,
                                )
                            }
                            let mut mls_group = group.mls_group.borrow_mut();
                            match mls_group.stage_commit(
                                &msg,
                                &proposal_store,
                                &[], // TODO: store key packages.
                                None,
                                &self.crypto,
                            ) {
                                Ok(staged_commit) => {
                                    mls_group.merge_commit(staged_commit);
                                }
                                Err(e) => {
                                    let s = format!("Error applying commit: {:?}", e);
                                    log::error!("{}", s);
                                    return Err(s);
                                }
                            }
                            group.pending_proposals.clear();
                        }
                    }
                }
            }
        }
        log::trace!("done with messages ...");

        for c in self.backend.list_clients()?.drain(..) {
            if c.id != self.identity.borrow().credential.credential().identity()
                && self
                    .contacts
                    .insert(
                        c.id.clone(),
                        Contact {
                            username: c.client_name,
                            public_keys: c.key_packages,
                            id: c.id,
                        },
                    )
                    .is_some()
            {
                log::trace!("Updated client {}", "");
            }
        }
        log::trace!("done with clients ...");

        Ok(messages_out)
    }

    /// Create a group with the given name.
    pub fn create_group(&mut self, name: String) {
        log::debug!("{} creates group {}", self.username, name);
        let group_id = name.as_bytes();
        let mut group_aad = group_id.to_vec();
        group_aad.extend(b" AAD");
        let kpb = self.identity.borrow_mut().update(&self.crypto);
        let mut config = MlsGroupConfig::default();
        config.add_ratchet_tree_extension = true;
        let mls_group = MlsGroup::new(
            group_id,
            CIPHERSUITE,
            &self.crypto,
            kpb,
            config,
            None, /* Initial PSK */
            None, /* MLS version */
        )
        .unwrap();
        let group = Group {
            group_id: group_id.to_vec(),
            group_name: name.clone(),
            members: Vec::new(),
            conversation: Conversation::default(),
            mls_group: RefCell::new(mls_group),
            group_aad,
            pending_proposals: Vec::new(),
        };
        if self
            .groups
            .borrow_mut()
            .insert(group_id.to_vec(), group)
            .is_some()
        {
            panic!("Group '{}' existed already", name);
        }
    }

    /// Invite user with the given name to the group.
    pub fn invite(&mut self, name: String, group: String) -> Result<(), String> {
        // First we need to get the key package for {id} from the DS.
        // We just take the first key package we get back from the server.
        let contact = match self.contacts.values().find(|c| c.username == name) {
            Some(v) => v,
            None => return Err(format!("No contact with name {} known.", name)),
        };
        let (_hash, key_package) = self
            .backend
            .get_client(&contact.id)
            .unwrap()
            .0
            .pop()
            .unwrap();

        // Build a proposal with this key package and do the MLS bits.
        let group_id = group.as_bytes();
        let mut groups = self.groups.borrow_mut();
        let group = match groups.get_mut(group_id) {
            Some(g) => g,
            None => return Err(format!("No group with name {} known.", group)),
        };
        let credentials = &self.identity.borrow().credential;
        // Framing parameters
        let framing_parameters = FramingParameters::new(&group.group_aad, WireFormat::MlsPlaintext);
        let add_proposal = group
            .mls_group
            .borrow()
            .create_add_proposal(framing_parameters, credentials, key_package, &self.crypto)
            .expect("Could not create proposal.");
        let proposal_store = ProposalStore::from_staged_proposal(
            StagedProposal::from_mls_plaintext(
                Config::ciphersuite(CIPHERSUITE).map_err(|e| format!("{}", e))?,
                &self.crypto,
                add_proposal.clone(),
            )
            .map_err(|e| format!("{}", e))?,
        );
        let params = CreateCommitParams::builder()
            .framing_parameters(framing_parameters)
            .credential_bundle(credentials)
            .proposal_store(&proposal_store)
            .force_self_update(false)
            .build();
        let (commit, welcome_msg, _kpb) = group
            .mls_group
            .borrow()
            .create_commit(params, &self.crypto)
            .expect("Error creating commit");
        let welcome_msg = welcome_msg.expect("Welcome message wasn't created by create_commit.");

        let staged_commit = group
            .mls_group
            .borrow_mut()
            .stage_commit(&commit, &proposal_store, &[], None, &self.crypto)
            .expect("error applying commit");
        group.mls_group.borrow_mut().merge_commit(staged_commit);

        // Send Welcome to the client.
        log::trace!("Sending welcome");
        self.backend
            .send_welcome(&welcome_msg)
            .expect("Error sending unwrap message");

        // Send proposal to the group.
        log::trace!("Sending proposal");
        let group = groups.get_mut(group_id).unwrap(); // XXX: not cool.
        let group_recipients = self.recipients(group);
        // TODO: the outgoing messages should use `MlsMessage` instead.
        let msg = GroupMessage::new(
            DsMlsMessage::Plaintext(VerifiableMlsPlaintext::from_plaintext(add_proposal, None)),
            &group_recipients,
        );
        self.backend.send_msg(&msg)?;

        // Send commit to the group.
        log::trace!("Sending commit");
        let msg = GroupMessage::new(
            DsMlsMessage::Plaintext(VerifiableMlsPlaintext::from_plaintext(commit, None)),
            &group_recipients,
        );
        self.backend.send_msg(&msg)?;

        // Update the group state
        group.members.push(contact.id.clone());

        Ok(())
    }

    /// Join a group with the provided welcome message.
    fn join_group(&self, welcome: Welcome) -> Result<(), String> {
        log::debug!("{} joining group ...", self.username);

        let kpb = self.identity.borrow_mut().update(&self.crypto);
        let mls_group = match MlsGroup::new_from_welcome(
            welcome,
            None, /* no public tree here, has to be in the extension */
            kpb,
            None, /* PSK fetcher */
            &self.crypto,
        ) {
            Ok(g) => g,
            Err(e) => {
                let s = format!("Error creating group from Welcome: {:?}", e);
                log::info!("{}", s);
                return Err(s);
            }
        };

        let group_id = mls_group.group_id();
        // XXX: Add application layer protocol for name etc.
        let group_name = String::from_utf8(group_id.to_vec()).unwrap();
        let group_aad = group_name.clone() + " AAD";
        let group_id = group_id.to_vec();

        // FIXME
        let tree = mls_group.tree();
        let leaf_count = tree.leaf_count();
        let mut members = Vec::new();
        for index in 0..leaf_count.as_usize() {
            let leaf = &tree.nodes[LeafIndex::from(index)];
            if let Some(leaf_node) = leaf.key_package() {
                members.push(leaf_node.credential().identity().to_vec());
            }
        }
        drop(tree);

        let group = Group {
            group_id: group_id.clone(),
            group_name: group_name.clone(),
            members,
            conversation: Conversation::default(),
            mls_group: RefCell::new(mls_group),
            group_aad: group_aad.as_bytes().to_vec(),
            pending_proposals: Vec::new(),
        };

        log::trace!("   {}", group_name);

        match self.groups.borrow_mut().insert(group_id, group) {
            Some(old) => Err(format!("Overrode the group {:?}", old.group_name)),
            None => Ok(()),
        }
    }
}
