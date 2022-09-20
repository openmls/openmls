use std::{cell::RefCell, collections::HashMap};

use ds_lib::{ClientKeyPackages, GroupMessage, Message};
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsCryptoProvider;

use super::{backend::Backend, conversation::Conversation, identity::Identity};

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

pub struct Contact {
    username: String,
    id: Vec<u8>,
    // We store multiple here but always only use the first one right now.
    #[allow(dead_code)]
    public_keys: ClientKeyPackages,
}

pub struct Group {
    group_name: String,
    conversation: Conversation,
    mls_group: RefCell<MlsGroup>,
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
            self.identity
                .borrow()
                .kpb
                .key_package()
                .hash_ref(self.crypto.crypto())
                .unwrap()
                .as_slice()
                .to_vec(),
            self.identity.borrow().kpb.key_package().clone(),
        )]
    }

    /// Get a list of clients in the group to send messages to.
    fn recipients(&self, group: &Group) -> Vec<Vec<u8>> {
        let mut recipients = Vec::new();

        let mls_group = group.mls_group.borrow();
        for member in mls_group.members() {
            if self.identity.borrow().credential.credential().identity()
                != member.credential().identity()
            {
                let contact = match self.contacts.get(member.credential().identity()) {
                    Some(c) => c.id.clone(),
                    None => panic!("There's a member in the group we don't know."),
                };
                recipients.push(contact);
            }
        }
        recipients
    }

    /// Return the last 100 messages sent to the group.
    pub fn read_msgs(&self, group_name: String) -> Result<Option<Vec<String>>, String> {
        let groups = self.groups.borrow();
        groups.get(group_name.as_bytes()).map_or_else(
            || Err("Unknown group".to_string()),
            |g| Ok(g.conversation.get(100).map(|messages| messages.to_vec())),
        )
    }

    /// Send an application message to the group.
    pub fn send_msg(&self, msg: &str, group: String) -> Result<(), String> {
        let groups = self.groups.borrow();
        let group = match groups.get(group.as_bytes()) {
            Some(g) => g,
            None => return Err("Unknown group".to_string()),
        };

        let message_out = group
            .mls_group
            .borrow_mut()
            .create_message(&self.crypto, msg.as_bytes())
            .map_err(|e| format!("{}", e))?;

        let msg = GroupMessage::new(message_out.into(), &self.recipients(group));
        log::debug!(" >>> send: {:?}", msg);
        self.backend.send_msg(&msg)?;

        // XXX: Need to update the client's local view of the conversation to include
        // the message they sent.

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

                    let group = match groups.get_mut(message.group_id().as_slice()) {
                        Some(g) => g,
                        None => {
                            log::error!(
                                "Error getting group {:?} for a message. Dropping message.",
                                message.group_id()
                            );
                            continue;
                        }
                    };
                    let mut mls_group = group.mls_group.borrow_mut();

                    let unverified_message = match mls_group.parse_message(message, &self.crypto) {
                        Ok(msg) => msg,
                        Err(e) => {
                            log::error!("Error parsing message: {:?} -  Dropping message.", e);
                            continue;
                        }
                    };

                    let processed_message = match mls_group.process_unverified_message(
                        unverified_message,
                        None,
                        &self.crypto,
                    ) {
                        Ok(msg) => msg,
                        Err(e) => {
                            log::error!(
                                "Error processing unverified message: {:?} -  Dropping message.",
                                e
                            );
                            continue;
                        }
                    };

                    match processed_message {
                        ProcessedMessage::ApplicationMessage(application_message) => {
                            let application_message =
                                String::from_utf8(application_message.into_bytes()).unwrap();
                            if group_name.is_none()
                                || group_name.clone().unwrap() == group.group_name
                            {
                                messages_out.push(application_message.clone());
                            }
                            group.conversation.add(application_message);
                        }
                        ProcessedMessage::ProposalMessage(_proposal_ptr) => {
                            // intentionally left blank.
                        }
                        ProcessedMessage::StagedCommitMessage(commit_ptr) => {
                            mls_group
                                .merge_staged_commit(*commit_ptr)
                                .expect("Failed to merge staged commit!");
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

        // NOTE: Since the DS currently doesn't distribute copies of the group's ratchet
        // tree, we need to include the ratchet_tree_extension.
        let group_config = MlsGroupConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();

        let mut mls_group = MlsGroup::new(
            &self.crypto,
            &group_config,
            GroupId::from_slice(group_id),
            kpb.key_package()
                .hash_ref(self.crypto.crypto())
                .expect("Failed to hash KeyPackage.")
                .as_slice(),
        )
        .expect("Failed to create MlsGroup");
        mls_group.set_aad(group_aad.as_slice());

        let group = Group {
            group_name: name.clone(),
            conversation: Conversation::default(),
            mls_group: RefCell::new(mls_group),
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
        let (_hash, joiner_key_package) = self
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

        let (out_messages, welcome) = group
            .mls_group
            .borrow_mut()
            .add_members(&self.crypto, &[joiner_key_package])
            .map_err(|e| format!("Failed to add member to group - {}", e))?;

        // First, process the invitation on our end.
        group
            .mls_group
            .borrow_mut()
            .merge_pending_commit()
            .expect("error merging pending commit");

        // Second, send Welcome to the joiner.
        log::trace!("Sending welcome");
        self.backend
            .send_welcome(&welcome)
            .expect("Error sending Welcome message");

        // Finally, send the MlsMessages to the group.
        log::trace!("Sending proposal");
        let group = groups.get_mut(group_id).unwrap(); // XXX: not cool.
        let group_recipients = self.recipients(group);

        let msg = GroupMessage::new(out_messages.into(), &group_recipients);
        self.backend.send_msg(&msg)?;

        Ok(())
    }

    /// Join a group with the provided welcome message.
    fn join_group(&self, welcome: Welcome) -> Result<(), String> {
        log::debug!("{} joining group ...", self.username);

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

        match self.groups.borrow_mut().insert(group_id, group) {
            Some(old) => Err(format!("Overrode the group {:?}", old.group_name)),
            None => Ok(()),
        }
    }
}
