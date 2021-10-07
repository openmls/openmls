//! This is a the OpenMLS client for the interop harness as described here:
//! https://github.com/mlswg/mls-implementations/tree/master/interop
//!
//! It is based on the Mock client written by Richard Barnes.

use clap::Clap;
use openmls::{
    ciphersuite::signable::Verifiable,
    group::tests::{
        kat_messages::{self, MessagesTestVector},
        kat_transcripts::{self, TranscriptTestVector},
    },
    prelude::*,
    schedule::kat_key_schedule::{self, KeyScheduleTestVector},
    tree::tests_and_kats::kats::{
        kat_encryption::{self, EncryptionTestVector},
        kat_tree_kem::{self, TreeKemTestVector},
        kat_treemath,
    },
};
use serde::{self, Serialize};
use std::{collections::HashMap, convert::TryFrom, fs::File, io::Write, sync::Mutex};
use tonic::{transport::Server, Request, Response, Status};

use mls_client::mls_client_server::{MlsClient, MlsClientServer};
use mls_client::*;

pub mod mls_client {
    tonic::include_proto!("mls_client");
}

const IMPLEMENTATION_NAME: &str = "OpenMLS";

impl TryFrom<i32> for TestVectorType {
    type Error = ();

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TestVectorType::TreeMath),
            1 => Ok(TestVectorType::Encryption),
            2 => Ok(TestVectorType::KeySchedule),
            3 => Ok(TestVectorType::Transcript),
            4 => Ok(TestVectorType::Treekem),
            5 => Ok(TestVectorType::Messages),
            _ => Err(()),
        }
    }
}

/// This struct contains the state for a single MLS client. The interop client
/// doesn't consider scenarios where a credential is re-used across groups, so
/// this simple structure is sufficient.
pub struct InteropGroup {
    group: MlsGroup,
    encrypt_handshake_messages: bool,
    credential_bundle: CredentialBundle,
    own_kpbs: Vec<KeyPackageBundle>,
}

/// This is the main state struct of the interop client. It keeps track of the
/// individual MLS clients, as well as pending key packages that it was told to
/// create. It also contains a transaction id map, that maps the `u32`
/// transaction ids to key package hashes.
pub struct MlsClientImpl {
    groups: Mutex<Vec<InteropGroup>>,
    pending_key_packages: Mutex<HashMap<Vec<u8>, (KeyPackageBundle, CredentialBundle)>>,
    /// Note that the client currently doesn't really use transaction ids and
    /// instead relies on the KeyPackage hash in the Welcome message to identify
    /// what key package to use when joining a group.
    transaction_id_map: Mutex<HashMap<u32, Vec<u8>>>,
}

impl MlsClientImpl {
    /// A simple constructor for `MlsClientImpl`.
    fn new() -> Self {
        MlsClientImpl {
            groups: Mutex::new(Vec::new()),
            pending_key_packages: Mutex::new(HashMap::new()),
            transaction_id_map: Mutex::new(HashMap::new()),
        }
    }
}

fn into_status(e: MlsGroupError) -> Status {
    let message = "managed group error ".to_string() + &e.to_string();
    tonic::Status::new(tonic::Code::Aborted, message)
}

fn to_ciphersuite(cs: u32) -> Result<&'static Ciphersuite, Status> {
    let cs_name = match CiphersuiteName::try_from(cs as u16) {
        Ok(cs_name) => cs_name,
        Err(_) => {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "ciphersuite not supported by OpenMLS",
            ));
        }
    };
    match Config::supported_ciphersuites()
        .iter()
        .find(|cs| cs.name() == cs_name)
    {
        Some(ciphersuite) => Ok(ciphersuite),
        None => {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "ciphersuite not supported by this configuration of OpenMLS",
            ));
        }
    }
}

fn into_bytes(obj: impl Serialize) -> Vec<u8> {
    serde_json::to_string_pretty(&obj)
        .expect("Error serializing test vectors")
        .as_bytes()
        .to_vec()
}

pub fn write(file_name: &str, payload: &[u8]) {
    let mut file = match File::create(file_name) {
        Ok(f) => f,
        Err(_) => panic!("Couldn't open file {}.", file_name),
    };
    file.write_all(payload)
        .expect("Error writing test vector file");
}

#[tonic::async_trait]
impl MlsClient for MlsClientImpl {
    async fn name(&self, _request: Request<NameRequest>) -> Result<Response<NameResponse>, Status> {
        println!("Got Name request");

        let response = NameResponse {
            name: IMPLEMENTATION_NAME.to_string(),
        };
        Ok(Response::new(response))
    }

    async fn supported_ciphersuites(
        &self,
        _request: tonic::Request<SupportedCiphersuitesRequest>,
    ) -> Result<tonic::Response<SupportedCiphersuitesResponse>, tonic::Status> {
        println!("Got SupportedCiphersuites request");

        let response = SupportedCiphersuitesResponse {
            ciphersuites: Config::supported_ciphersuite_names()
                .iter()
                .map(|cs| *cs as u32)
                .collect(),
        };

        Ok(Response::new(response))
    }

    async fn generate_test_vector(
        &self,
        request: tonic::Request<GenerateTestVectorRequest>,
    ) -> Result<tonic::Response<GenerateTestVectorResponse>, tonic::Status> {
        println!("Got GenerateTestVector request");

        let obj = request.get_ref();
        let (type_msg, test_vector) = match TestVectorType::try_from(obj.test_vector_type) {
            Ok(TestVectorType::TreeMath) => {
                let kat_treemath = kat_treemath::generate_test_vector(obj.n_leaves);
                let kat_bytes = into_bytes(kat_treemath);
                ("Tree math", kat_bytes)
            }
            Ok(TestVectorType::Encryption) => {
                let ciphersuite = to_ciphersuite(obj.cipher_suite)?;
                let kat_encryption = kat_encryption::generate_test_vector(
                    obj.n_generations,
                    obj.n_leaves,
                    ciphersuite,
                );
                let kat_bytes = into_bytes(kat_encryption);
                ("Encryption", kat_bytes)
            }
            Ok(TestVectorType::KeySchedule) => {
                let ciphersuite = to_ciphersuite(obj.cipher_suite)?;
                let kat_key_schedule =
                    kat_key_schedule::generate_test_vector(obj.n_epochs as u64, ciphersuite);
                let kat_bytes = into_bytes(kat_key_schedule);
                ("Key Schedule", kat_bytes)
            }
            Ok(TestVectorType::Transcript) => {
                let ciphersuite = to_ciphersuite(obj.cipher_suite)?;
                let kat_transcript = kat_transcripts::generate_test_vector(ciphersuite);
                let kat_bytes = into_bytes(kat_transcript);
                ("Transcript", kat_bytes)
            }
            Ok(TestVectorType::Treekem) => {
                let ciphersuite = to_ciphersuite(obj.cipher_suite)?;
                let kat_tree_kem =
                    kat_tree_kem::generate_test_vector(obj.n_leaves as u32, ciphersuite);
                let kat_bytes = into_bytes(kat_tree_kem);
                ("TreeKEM", kat_bytes)
            }
            Ok(TestVectorType::Messages) => {
                let ciphersuite: &'static Ciphersuite =
                    Config::supported_ciphersuites().as_ref().first().unwrap();
                let kat_messages = kat_messages::generate_test_vector(ciphersuite);
                let kat_bytes = into_bytes(kat_messages);
                ("Messages", kat_bytes)
            }
            Err(_) => {
                return Err(tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "Invalid test vector type",
                ));
            }
        };
        println!("{} test vector request", type_msg);

        let response = GenerateTestVectorResponse { test_vector };

        Ok(Response::new(response))
    }

    async fn verify_test_vector(
        &self,
        request: tonic::Request<VerifyTestVectorRequest>,
    ) -> Result<tonic::Response<VerifyTestVectorResponse>, tonic::Status> {
        println!("Got VerifyTestVector request");

        let obj = request.get_ref();
        let (type_msg, _result) = match TestVectorType::try_from(obj.test_vector_type) {
            Ok(TestVectorType::TreeMath) => {
                write(&format!("mlspp_treemath.json"), &obj.test_vector);
                let kat_treemath = match serde_json::from_slice(&obj.test_vector) {
                    Ok(test_vector) => test_vector,
                    Err(_) => {
                        return Err(tonic::Status::new(
                            tonic::Code::InvalidArgument,
                            "Couldn't decode treemath test vector.",
                        ));
                    }
                };
                match kat_treemath::run_test_vector(kat_treemath) {
                    Ok(result) => ("Tree math", result),
                    Err(e) => {
                        let message = "Error while running treemath test vector: ".to_string()
                            + &e.to_string();
                        return Err(tonic::Status::new(tonic::Code::Aborted, message));
                    }
                }
            }
            Ok(TestVectorType::Encryption) => {
                let kat_encryption: EncryptionTestVector =
                    match serde_json::from_slice(&obj.test_vector) {
                        Ok(test_vector) => test_vector,
                        Err(_) => {
                            return Err(tonic::Status::new(
                                tonic::Code::InvalidArgument,
                                "Couldn't decode encryption test vector.",
                            ));
                        }
                    };
                write(
                    &format!(
                        "mlspp_encryption_{}_{}.json",
                        kat_encryption.cipher_suite, kat_encryption.n_leaves
                    ),
                    &obj.test_vector,
                );
                match kat_encryption::run_test_vector(kat_encryption) {
                    Ok(result) => ("Encryption", result),
                    Err(e) => {
                        let message = "Error while running encryption test vector: ".to_string()
                            + &e.to_string();
                        return Err(tonic::Status::new(tonic::Code::Aborted, message));
                    }
                }
            }
            Ok(TestVectorType::KeySchedule) => {
                let kat_key_schedule: KeyScheduleTestVector =
                    match serde_json::from_slice(&obj.test_vector) {
                        Ok(test_vector) => test_vector,
                        Err(_) => {
                            return Err(tonic::Status::new(
                                tonic::Code::InvalidArgument,
                                "Couldn't decode key schedule test vector.",
                            ));
                        }
                    };
                write(
                    &format!("mlspp_key_schedule_{}.json", kat_key_schedule.cipher_suite),
                    &obj.test_vector,
                );
                match kat_key_schedule::run_test_vector(kat_key_schedule) {
                    Ok(result) => ("Key Schedule", result),
                    Err(e) => {
                        let message = "Error while running key schedule test vector: ".to_string()
                            + &e.to_string();
                        return Err(tonic::Status::new(tonic::Code::Aborted, message));
                    }
                }
            }
            Ok(TestVectorType::Transcript) => {
                let kat_transcript: TranscriptTestVector =
                    match serde_json::from_slice(&obj.test_vector) {
                        Ok(test_vector) => test_vector,
                        Err(_) => {
                            println!("{}", String::from_utf8_lossy(&obj.test_vector));
                            return Err(tonic::Status::new(
                                tonic::Code::InvalidArgument,
                                "Couldn't decode transcript test vector.",
                            ));
                        }
                    };
                write(
                    &format!("mlspp_transcript_{}.json", kat_transcript.cipher_suite),
                    &obj.test_vector,
                );
                match kat_transcripts::run_test_vector(kat_transcript) {
                    Ok(result) => ("Transcript", result),
                    Err(e) => {
                        let message = "Error while running transcript test vector: ".to_string()
                            + &e.to_string();
                        return Err(tonic::Status::new(tonic::Code::Aborted, message));
                    }
                }
            }
            Ok(TestVectorType::Treekem) => {
                let kat_tree_kem: TreeKemTestVector = match serde_json::from_slice(&obj.test_vector)
                {
                    Ok(test_vector) => test_vector,
                    Err(_) => {
                        return Err(tonic::Status::new(
                            tonic::Code::InvalidArgument,
                            "Couldn't decode TreeKEM test vector.",
                        ));
                    }
                };
                write(
                    &format!("mlspp_tree_kem_{}.json", kat_tree_kem.cipher_suite),
                    &obj.test_vector,
                );
                match kat_tree_kem::run_test_vector(kat_tree_kem) {
                    Ok(result) => ("TreeKEM", result),
                    Err(e) => {
                        let message = "Error while running TreeKEM test vector: ".to_string()
                            + &e.to_string();
                        return Err(tonic::Status::new(tonic::Code::Aborted, message));
                    }
                }
            }
            Ok(TestVectorType::Messages) => {
                let kat_messages: MessagesTestVector =
                    match serde_json::from_slice(&obj.test_vector) {
                        Ok(test_vector) => test_vector,
                        Err(_) => {
                            return Err(tonic::Status::new(
                                tonic::Code::InvalidArgument,
                                "Couldn't decode messages test vector.",
                            ));
                        }
                    };
                write("mlspp_messages_{}.json", &obj.test_vector);
                match kat_messages::run_test_vector(kat_messages) {
                    Ok(result) => ("Messages", result),
                    Err(e) => {
                        let message = "Error while running messages test vector: ".to_string()
                            + &e.to_string();
                        return Err(tonic::Status::new(tonic::Code::Aborted, message));
                    }
                }
            }
            Err(_) => {
                return Err(tonic::Status::new(
                    tonic::Code::Unimplemented,
                    "Invalid test vector type",
                ));
            }
        };
        println!("{} test vector request successful", type_msg);

        Ok(Response::new(VerifyTestVectorResponse::default()))
    }

    async fn create_group(
        &self,
        request: tonic::Request<CreateGroupRequest>,
    ) -> Result<tonic::Response<CreateGroupResponse>, tonic::Status> {
        let create_group_request = request.get_ref();

        let ciphersuite =
            CiphersuiteName::try_from(create_group_request.cipher_suite as u16).unwrap();
        let credential_bundle = CredentialBundle::new(
            "OpenMLS".bytes().collect(),
            CredentialType::Basic,
            SignatureScheme::from(ciphersuite),
        )
        .unwrap();
        let key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite], &credential_bundle, vec![]).unwrap();
        let mut config = MlsGroupConfig::default();
        config.add_ratchet_tree_extension = true;
        let group = MlsGroup::new(
            &create_group_request.group_id,
            ciphersuite,
            key_package_bundle,
            config,
            None,
            ProtocolVersion::default(),
        )
        .map_err(|e| into_status(e))?;

        let interop_group = InteropGroup {
            credential_bundle,
            encrypt_handshake_messages: create_group_request.encrypt_handshake,
            group,
            own_kpbs: Vec::new(),
        };

        let mut groups = self.groups.lock().unwrap();
        let state_id = groups.len() as u32;
        groups.push(interop_group);

        Ok(Response::new(CreateGroupResponse { state_id }))
    }

    async fn create_key_package(
        &self,
        request: tonic::Request<CreateKeyPackageRequest>,
    ) -> Result<tonic::Response<CreateKeyPackageResponse>, tonic::Status> {
        let create_kp_request = request.get_ref();

        let ciphersuite = to_ciphersuite(create_kp_request.cipher_suite)?;
        let credential_bundle = CredentialBundle::new(
            "OpenMLS".bytes().collect(),
            CredentialType::Basic,
            SignatureScheme::from(ciphersuite.name()),
        )
        .unwrap();
        let key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite.name()], &credential_bundle, vec![]).unwrap();
        let key_package = key_package_bundle.key_package().clone();
        let mut transaction_id_map = self.transaction_id_map.lock().unwrap();
        let transaction_id = transaction_id_map.len() as u32;
        transaction_id_map.insert(transaction_id, key_package.hash());

        self.pending_key_packages.lock().unwrap().insert(
            key_package_bundle.key_package().hash(),
            (key_package_bundle, credential_bundle),
        );

        Ok(Response::new(CreateKeyPackageResponse {
            transaction_id,
            key_package: key_package
                .tls_serialize_detached()
                .expect("error serializing key package"),
        }))
    }

    async fn join_group(
        &self,
        request: tonic::Request<JoinGroupRequest>,
    ) -> Result<tonic::Response<JoinGroupResponse>, tonic::Status> {
        let join_group_request = request.get_ref();

        let welcome = Welcome::tls_deserialize(&mut join_group_request.welcome.as_slice()).unwrap();
        let mut pending_key_packages = self.pending_key_packages.lock().unwrap();
        let (kpb, credential_bundle) = welcome
            .secrets()
            .iter()
            .find_map(|egs| pending_key_packages.remove(egs.key_package_hash.as_slice()))
            .ok_or(tonic::Status::new(
                tonic::Code::NotFound,
                "No key package could be found for the given Welcome message.",
            ))?;
        let group =
            MlsGroup::new_from_welcome(welcome, None, kpb, None).map_err(|e| into_status(e))?;

        let interop_group = InteropGroup {
            credential_bundle,
            encrypt_handshake_messages: join_group_request.encrypt_handshake,
            group,
            own_kpbs: Vec::new(),
        };

        let mut groups = self.groups.lock().unwrap();
        let state_id = groups.len() as u32;
        groups.push(interop_group);

        Ok(Response::new(JoinGroupResponse { state_id }))
    }

    async fn external_join(
        &self,
        _request: tonic::Request<ExternalJoinRequest>,
    ) -> Result<tonic::Response<ExternalJoinResponse>, tonic::Status> {
        Err(tonic::Status::new(
            tonic::Code::Unimplemented,
            "external join is not yet supported by OpenMLS",
        ))
    }

    async fn public_group_state(
        &self,
        _request: tonic::Request<PublicGroupStateRequest>,
    ) -> Result<tonic::Response<PublicGroupStateResponse>, tonic::Status> {
        Err(tonic::Status::new(
            tonic::Code::Unimplemented,
            "exporting public group state is not yet supported by OpenMLS",
        ))
    }

    async fn state_auth(
        &self,
        request: tonic::Request<StateAuthRequest>,
    ) -> Result<tonic::Response<StateAuthResponse>, tonic::Status> {
        let state_auth_request = request.get_ref();

        let groups = self.groups.lock().unwrap();
        let interop_group =
            groups
                .get(state_auth_request.state_id as usize)
                .ok_or(tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "unknown state_id",
                ))?;

        let state_auth_secret = interop_group.group.authentication_secret();

        Ok(Response::new(StateAuthResponse { state_auth_secret }))
    }

    async fn export(
        &self,
        request: tonic::Request<ExportRequest>,
    ) -> Result<tonic::Response<ExportResponse>, tonic::Status> {
        let export_request = request.get_ref();

        let groups = self.groups.lock().unwrap();
        let interop_group =
            groups
                .get(export_request.state_id as usize)
                .ok_or(tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "unknown state_id",
                ))?;
        let exported_secret = interop_group
            .group
            .export_secret(
                &export_request.label,
                &export_request.context,
                export_request.key_length as usize,
            )
            .map_err(|e| into_status(e))?;

        Ok(Response::new(ExportResponse { exported_secret }))
    }

    async fn protect(
        &self,
        request: tonic::Request<ProtectRequest>,
    ) -> Result<tonic::Response<ProtectResponse>, tonic::Status> {
        let protect_request = request.get_ref();

        let mut groups = self.groups.lock().unwrap();
        let interop_group =
            groups
                .get_mut(protect_request.state_id as usize)
                .ok_or(tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "unknown state_id",
                ))?;

        let ciphertext = interop_group
            .group
            .create_application_message(
                &[],
                &protect_request.application_data,
                &interop_group.credential_bundle,
                10,
            )
            .map_err(|e| into_status(e))?
            .tls_serialize_detached()
            .map_err(|_| Status::aborted("failed to serialize ciphertext"))?;
        Ok(Response::new(ProtectResponse { ciphertext }))
    }

    async fn unprotect(
        &self,
        request: tonic::Request<UnprotectRequest>,
    ) -> Result<tonic::Response<UnprotectResponse>, tonic::Status> {
        let unprotect_request = request.get_ref();

        let mut groups = self.groups.lock().unwrap();
        let interop_group =
            groups
                .get_mut(unprotect_request.state_id as usize)
                .ok_or(tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "unknown state_id",
                ))?;

        let message = MlsCiphertext::tls_deserialize(&mut unprotect_request.ciphertext.as_slice())
            .map_err(|_| Status::aborted("failed to deserialize ciphertext"))?;
        let application_data = interop_group
            .group
            .decrypt(&message)
            .map_err(|e| into_status(e.into()))?
            .as_application_message()
            .map_err(|e| into_status(e.into()))?
            .to_vec();

        Ok(Response::new(UnprotectResponse { application_data }))
    }

    async fn store_psk(
        &self,
        _request: tonic::Request<StorePskRequest>,
    ) -> Result<tonic::Response<StorePskResponse>, tonic::Status> {
        Ok(Response::new(StorePskResponse::default()))
    }

    async fn add_proposal(
        &self,
        request: tonic::Request<AddProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let add_proposal_request = request.get_ref();

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(add_proposal_request.state_id as usize)
            .ok_or(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "unknown state_id",
            ))?;

        let key_package =
            KeyPackage::tls_deserialize(&mut add_proposal_request.key_package.as_slice())
                .map_err(|_| Status::aborted("failed to deserialize key package"))?;
        let proposal = interop_group
            .group
            .create_add_proposal(&[], &interop_group.credential_bundle, key_package)
            .map_err(|e| into_status(e))?;

        let proposal = if interop_group.encrypt_handshake_messages {
            interop_group
                .group
                .encrypt(proposal, 10)
                .map_err(|_| Status::aborted("failed to encrypt proposal"))?
                .tls_serialize_detached()
                .map_err(|_| Status::aborted("failed to serialize proposal"))?
        } else {
            proposal
                .tls_serialize_detached()
                .map_err(|_| Status::aborted("failed to serialize proposal"))?
        };

        Ok(Response::new(ProposalResponse { proposal }))
    }

    async fn update_proposal(
        &self,
        request: tonic::Request<UpdateProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let update_proposal_request = request.get_ref();

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(update_proposal_request.state_id as usize)
            .ok_or(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "unknown state_id",
            ))?;
        let key_package_bundle = KeyPackageBundle::new(
            &[interop_group.group.ciphersuite().name()],
            &interop_group.credential_bundle,
            vec![],
        )
        .unwrap();
        let proposal = interop_group
            .group
            .create_update_proposal(
                &[],
                &interop_group.credential_bundle,
                key_package_bundle.key_package().clone(),
            )
            .map_err(|e| into_status(e))?;

        interop_group.own_kpbs.push(key_package_bundle);

        let proposal = if interop_group.encrypt_handshake_messages {
            interop_group
                .group
                .encrypt(proposal, 10)
                .map_err(|_| Status::aborted("failed to encrypt proposal"))?
                .tls_serialize_detached()
                .map_err(|_| Status::aborted("failed to serialize proposal"))?
        } else {
            proposal
                .tls_serialize_detached()
                .map_err(|_| Status::aborted("failed to serialize proposal"))?
        };

        Ok(Response::new(ProposalResponse { proposal }))
    }

    async fn remove_proposal(
        &self,
        request: tonic::Request<RemoveProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let remove_proposal_request = request.get_ref();

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(remove_proposal_request.state_id as usize)
            .ok_or(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "unknown state_id",
            ))?;

        let proposal = interop_group
            .group
            .create_remove_proposal(
                &[],
                &interop_group.credential_bundle,
                LeafIndex::from(remove_proposal_request.removed as usize),
            )
            .map_err(|e| into_status(e))?;

        let proposal = if interop_group.encrypt_handshake_messages {
            interop_group
                .group
                .encrypt(proposal, 10)
                .map_err(|_| Status::aborted("failed to encrypt proposal"))?
                .tls_serialize_detached()
                .map_err(|_| Status::aborted("failed to serialize proposal"))?
        } else {
            proposal
                .tls_serialize_detached()
                .map_err(|_| Status::aborted("failed to serialize proposal"))?
        };

        Ok(Response::new(ProposalResponse { proposal }))
    }

    async fn psk_proposal(
        &self,
        _request: tonic::Request<PskProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        Ok(Response::new(ProposalResponse::default()))
    }

    async fn re_init_proposal(
        &self,
        _request: tonic::Request<ReInitProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        Ok(Response::new(ProposalResponse::default()))
    }

    async fn app_ack_proposal(
        &self,
        _request: tonic::Request<AppAckProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        Ok(Response::new(ProposalResponse::default()))
    }

    async fn commit(
        &self,
        request: tonic::Request<CommitRequest>,
    ) -> Result<tonic::Response<CommitResponse>, tonic::Status> {
        let commit_request = request.get_ref();

        let mut groups = self.groups.lock().unwrap();
        let interop_group =
            groups
                .get_mut(commit_request.state_id as usize)
                .ok_or(tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "unknown state_id",
                ))?;

        let mut proposal_plaintexts = Vec::new();
        for bytes in &commit_request.by_reference {
            let pt = if interop_group.encrypt_handshake_messages {
                let ct = MlsCiphertext::tls_deserialize(&mut bytes.as_slice())
                    .map_err(|_| Status::aborted("failed to deserialize ciphertext"))?;
                interop_group
                    .group
                    .decrypt(&ct)
                    .map_err(|_| Status::aborted("failed to decrypt ciphertext"))?
            } else {
                let credential = interop_group.credential_bundle.credential();
                VerifiableMlsPlaintext::tls_deserialize(&mut bytes.as_slice())
                    .map_err(|_| Status::aborted("failed to deserialize plaintext"))?
                    .verify(credential)
                    .map_err(|_| Status::aborted("couldn't verify given plaintext"))?
            };
            proposal_plaintexts.push(pt);
        }
        let mut proposals_by_reference = Vec::new();
        for proposal in &proposal_plaintexts {
            proposals_by_reference.push(proposal);
        }

        let mut plaintexts = Vec::new();
        for bytes in &commit_request.by_reference {
            let pt = if interop_group.encrypt_handshake_messages {
                let ct = MlsCiphertext::tls_deserialize(&mut bytes.as_slice())
                    .map_err(|_| Status::aborted("failed to deserialize ciphertext"))?;
                interop_group
                    .group
                    .decrypt(&ct)
                    .map_err(|_| Status::aborted("failed to decrypt ciphertext"))?
            } else {
                let credential = interop_group.credential_bundle.credential();
                VerifiableMlsPlaintext::tls_deserialize(&mut bytes.as_slice())
                    .map_err(|_| Status::aborted("failed to deserialize plaintext"))?
                    .verify(credential)
                    .map_err(|_| Status::aborted("couldn't verify given plaintext"))?
            };
            plaintexts.push(pt);
        }
        let mut proposals_by_value = Vec::new();
        for pt in &plaintexts {
            match pt.content() {
                MlsPlaintextContentType::Proposal(proposal) => proposals_by_value.push(proposal),
                _ => return Err(Status::aborted("plaintext did not contain a proposal")),
            };
        }

        let (commit, option_welcome, option_kpb) = interop_group
            .group
            .create_commit(
                &[],
                &interop_group.credential_bundle,
                &proposals_by_reference,
                &proposals_by_value,
                false,
                None,
            )
            .map_err(|e| into_status(e))?;

        if let Some(kpb) = option_kpb {
            interop_group.own_kpbs.push(kpb)
        }

        let commit = if interop_group.encrypt_handshake_messages {
            interop_group
                .group
                .encrypt(commit, 10)
                .map_err(|_| Status::aborted("failed to encrypt commit"))?
                .tls_serialize_detached()
                .map_err(|_| Status::aborted("failed to serialize commit"))?
        } else {
            commit
                .tls_serialize_detached()
                .map_err(|_| Status::aborted("failed to serialize commit"))?
        };

        let welcome = if let Some(welcome) = option_welcome {
            welcome
                .tls_serialize_detached()
                .map_err(|_| Status::aborted("failed to serialize welcome"))?
        } else {
            vec![]
        };

        Ok(Response::new(CommitResponse { commit, welcome }))
    }

    async fn handle_commit(
        &self,
        request: tonic::Request<HandleCommitRequest>,
    ) -> Result<tonic::Response<HandleCommitResponse>, tonic::Status> {
        let handle_commit_request = request.get_ref();

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(handle_commit_request.state_id as usize)
            .ok_or(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "unknown state_id",
            ))?;

        let commit = if interop_group.encrypt_handshake_messages {
            let ct = MlsCiphertext::tls_deserialize(&mut handle_commit_request.commit.as_slice())
                .map_err(|_| Status::aborted("failed to deserialize ciphertext"))?;
            interop_group
                .group
                .decrypt(&ct)
                .map_err(|_| Status::aborted("failed to decrypt ciphertext"))?
        } else {
            let credential = interop_group.credential_bundle.credential();
            VerifiableMlsPlaintext::tls_deserialize(&mut handle_commit_request.commit.as_slice())
                .map_err(|_| Status::aborted("failed to deserialize plaintext"))?
                .verify(credential)
                .map_err(|_| Status::aborted("couldn't verify given plaintext"))?
        };

        let mut proposal_plaintexts = Vec::new();
        for bytes in &handle_commit_request.proposal {
            let pt = if interop_group.encrypt_handshake_messages {
                let ct = MlsCiphertext::tls_deserialize(&mut bytes.as_slice())
                    .map_err(|_| Status::aborted("failed to deserialize ciphertext"))?;
                interop_group
                    .group
                    .decrypt(&ct)
                    .map_err(|_| Status::aborted("failed to decrypt ciphertext"))?
            } else {
                let credential = interop_group.credential_bundle.credential();
                VerifiableMlsPlaintext::tls_deserialize(&mut bytes.as_slice())
                    .map_err(|_| Status::aborted("failed to deserialize plaintext"))?
                    .verify(credential)
                    .map_err(|_| Status::aborted("couldn't verify given plaintext"))?
            };
            proposal_plaintexts.push(pt);
        }
        let mut proposals_by_reference = Vec::new();
        for proposal in &proposal_plaintexts {
            proposals_by_reference.push(proposal);
        }

        interop_group
            .group
            .apply_commit(
                &commit,
                &proposals_by_reference,
                &interop_group.own_kpbs,
                None,
            )
            .map_err(|e| into_status(e))?;

        Ok(Response::new(HandleCommitResponse {
            state_id: handle_commit_request.state_id,
        }))
    }
}

#[derive(Clap)]
struct Opts {
    #[clap(short, long, default_value = "[::1]")]
    host: String,

    #[clap(short, long, default_value = "50051")]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = Opts::parse();
    pretty_env_logger::init();

    let addr = format!("{}:{}", opts.host, opts.port).parse().unwrap();
    let mls_client_impl = MlsClientImpl::new();

    println!("Listening on {}", addr);

    Server::builder()
        .add_service(MlsClientServer::new(mls_client_impl))
        .serve(addr)
        .await?;

    Ok(())
}
