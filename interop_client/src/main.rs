//! This is a the OpenMLS client for the interop harness as described here:
//! https://github.com/mlswg/mls-implementations/tree/master/interop
//!
//! It is based on the Mock client written by Richard Barnes.

use clap::Clap;
use openmls::{
    group::tests::kat_messages::{self, MessagesTestVector},
    group::tests::kat_transcripts::{self, TranscriptTestVector},
    prelude::*,
    schedule::kat_key_schedule::{self, KeyScheduleTestVector},
    tree::{
        self,
        tests::kat_encryption::EncryptionTestVector,
        tests::kat_tree_kem::{self, TreeKemTestVector},
    },
};
use serde::{self, Serialize};
use std::{collections::HashMap, convert::TryFrom, fs::File, io::Write, sync::Mutex};
use tonic::{transport::Server, Request, Response, Status};
use tree::tests::{kat_encryption, kat_treemath};

use tls_codec::Serialize as TLSSerialize;

use mls_client::mls_client_server::{MlsClient, MlsClientServer};
// TODO(RLB) Convert this back to more specific `use` directives
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

pub struct MlsClientImpl {
    client: Mutex<ManagedClient>,
    state_id_map: Mutex<HashMap<u32, GroupId>>,
    transaction_id_map: Mutex<HashMap<u32, Vec<u8>>>,
}

impl MlsClientImpl {
    fn new() -> Self {
        MlsClientImpl {
            client: Mutex::new(ManagedClient::new(
                "OpenMLS Client".as_bytes().to_vec(),
                ManagedClientConfig::default_tests(),
            )),
            state_id_map: Mutex::new(HashMap::new()),
            transaction_id_map: Mutex::new(HashMap::new()),
        }
    }
}

fn to_status(e: ManagedClientError) -> Status {
    let message = "client error ".to_string() + &e.to_string();
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

fn to_bytes(obj: impl Serialize) -> Vec<u8> {
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
                let kat_bytes = to_bytes(kat_treemath);
                ("Tree math", kat_bytes)
            }
            Ok(TestVectorType::Encryption) => {
                let ciphersuite = to_ciphersuite(obj.cipher_suite)?;
                let kat_encryption = kat_encryption::generate_test_vector(
                    obj.n_generations,
                    obj.n_leaves,
                    ciphersuite,
                );
                let kat_bytes = to_bytes(kat_encryption);
                ("Encryption", kat_bytes)
            }
            Ok(TestVectorType::KeySchedule) => {
                let ciphersuite = to_ciphersuite(obj.cipher_suite)?;
                let kat_key_schedule =
                    kat_key_schedule::generate_test_vector(obj.n_epochs as u64, ciphersuite);
                let kat_bytes = to_bytes(kat_key_schedule);
                ("Key Schedule", kat_bytes)
            }
            Ok(TestVectorType::Transcript) => {
                let ciphersuite = to_ciphersuite(obj.cipher_suite)?;
                let kat_transcript = kat_transcripts::generate_test_vector(ciphersuite);
                let kat_bytes = to_bytes(kat_transcript);
                ("Transcript", kat_bytes)
            }
            Ok(TestVectorType::Treekem) => {
                let ciphersuite = to_ciphersuite(obj.cipher_suite)?;
                let kat_tree_kem =
                    kat_tree_kem::generate_test_vector(obj.n_leaves as u32, ciphersuite);
                let kat_bytes = to_bytes(kat_tree_kem);
                ("TreeKEM", kat_bytes)
            }
            Ok(TestVectorType::Messages) => {
                let ciphersuite: &'static Ciphersuite =
                    Config::supported_ciphersuites().as_ref().first().unwrap();
                let kat_messages = kat_messages::generate_test_vector(ciphersuite);
                let kat_bytes = to_bytes(kat_messages);
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

        let handshake_message_format = if create_group_request.encrypt_handshake {
            HandshakeMessageFormat::Ciphertext
        } else {
            HandshakeMessageFormat::Plaintext
        };
        let managed_group_config = ManagedGroupConfig::new(
            handshake_message_format,
            UpdatePolicy::default(),
            10,
            0,
            ManagedGroupCallbacks::default(),
        );
        let group_id = GroupId::from_slice(&create_group_request.group_id);
        self.client
            .lock()
            .unwrap()
            .create_group(
                group_id.clone(),
                Some(&managed_group_config),
                Some(CiphersuiteName::try_from(create_group_request.cipher_suite as u16).unwrap()),
            )
            .map_err(|e| to_status(e))?;
        let mut state_id_map = self.state_id_map.lock().unwrap();
        let state_id = state_id_map.len() as u32;
        state_id_map.insert(state_id, group_id);
        Ok(Response::new(CreateGroupResponse { state_id }))
    }

    async fn create_key_package(
        &self,
        request: tonic::Request<CreateKeyPackageRequest>,
    ) -> Result<tonic::Response<CreateKeyPackageResponse>, tonic::Status> {
        let create_kp_request = request.get_ref();

        let ciphersuite = to_ciphersuite(create_kp_request.cipher_suite)?;
        let key_package = self
            .client
            .lock()
            .unwrap()
            .generate_key_package(&[ciphersuite.name()])
            .map_err(|e| to_status(e))?;
        let mut transaction_id_map = self.transaction_id_map.lock().unwrap();
        let transaction_id = transaction_id_map.len() as u32;
        transaction_id_map.insert(transaction_id, key_package.hash());

        Ok(Response::new(CreateKeyPackageResponse {
            transaction_id,
            key_package: key_package.encode_detached().unwrap(),
        }))
    }

    async fn join_group(
        &self,
        request: tonic::Request<JoinGroupRequest>,
    ) -> Result<tonic::Response<JoinGroupResponse>, tonic::Status> {
        let join_group_request = request.get_ref();

        let handshake_message_format = if join_group_request.encrypt_handshake {
            HandshakeMessageFormat::Ciphertext
        } else {
            HandshakeMessageFormat::Plaintext
        };
        let managed_group_config = ManagedGroupConfig::new(
            handshake_message_format,
            UpdatePolicy::default(),
            10,
            0,
            ManagedGroupCallbacks::default(),
        );

        let group_id = self
            .client
            .lock()
            .unwrap()
            .process_welcome(
                Some(&managed_group_config),
                Welcome::decode_detached(&join_group_request.welcome).unwrap(),
                None,
            )
            .map_err(|e| to_status(e))?;

        let mut state_id_map = self.state_id_map.lock().unwrap();
        let state_id = state_id_map.len() as u32;
        state_id_map.insert(state_id, group_id);

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
        //Ok(Response::new(ExternalJoinResponse::default())) // TODO
    }

    async fn public_group_state(
        &self,
        _request: tonic::Request<PublicGroupStateRequest>,
    ) -> Result<tonic::Response<PublicGroupStateResponse>, tonic::Status> {
        Err(tonic::Status::new(
            tonic::Code::Unimplemented,
            "exporting public group state is not yet supported by OpenMLS",
        ))
        //Ok(Response::new(PublicGroupStateResponse::default())) // TODO
    }

    async fn state_auth(
        &self,
        request: tonic::Request<StateAuthRequest>,
    ) -> Result<tonic::Response<StateAuthResponse>, tonic::Status> {
        let state_auth_request = request.get_ref();

        let group_id = self
            .state_id_map
            .lock()
            .unwrap()
            .get(&state_auth_request.state_id)
            .ok_or(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "unknown state_id",
            ))?
            // Cloning here to avoid potential poisoning of the state_id_map.
            .clone();
        let state_auth_secret = self
            .client
            .lock()
            .unwrap()
            .authentication_secret(&group_id)
            .map_err(|e| to_status(e))?;

        Ok(Response::new(StateAuthResponse { state_auth_secret }))
    }

    async fn export(
        &self,
        request: tonic::Request<ExportRequest>,
    ) -> Result<tonic::Response<ExportResponse>, tonic::Status> {
        let export_request = request.get_ref();

        let group_id = self
            .state_id_map
            .lock()
            .unwrap()
            .get(&export_request.state_id)
            .ok_or(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "unknown state_id",
            ))?
            // Cloning here to avoid potential poisoning of the state_id_map.
            .clone();
        let exported_secret = self
            .client
            .lock()
            .unwrap()
            .export_secret(
                &group_id,
                &export_request.label,
                &export_request.context,
                export_request.key_length as usize,
            )
            .map_err(|e| to_status(e))?;

        Ok(Response::new(ExportResponse { exported_secret }))
    }

    async fn protect(
        &self,
        request: tonic::Request<ProtectRequest>,
    ) -> Result<tonic::Response<ProtectResponse>, tonic::Status> {
        let protect_request = request.get_ref();

        let group_id = self
            .state_id_map
            .lock()
            .unwrap()
            .get(&protect_request.state_id)
            .ok_or(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "unknown state_id",
            ))?
            // Cloning here to avoid potential poisoning of the state_id_map.
            .clone();
        let ciphertext = self
            .client
            .lock()
            .unwrap()
            .create_message(&group_id, &protect_request.application_data)
            .map_err(|e| to_status(e))?
            .tls_serialize_detached()
            .map_err(|_| Status::aborted("failed to serialize ciphertext"))?;
        Ok(Response::new(ProtectResponse { ciphertext }))
    }

    async fn unprotect(
        &self,
        request: tonic::Request<UnprotectRequest>,
    ) -> Result<tonic::Response<UnprotectResponse>, tonic::Status> {
        let unprotect_request = request.get_ref();

        let group_id = self
            .state_id_map
            .lock()
            .unwrap()
            .get(&unprotect_request.state_id)
            .ok_or(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "unknown state_id",
            ))?
            // Cloning here to avoid potential poisoning of the state_id_map.
            .clone();
        let message = MLSCiphertext::decode_detached(&unprotect_request.ciphertext)
            .map_err(|_| Status::aborted("failed to deserialize ciphertext"))?;
        let events = self
            .client
            .lock()
            .unwrap()
            .process_messages(&group_id, vec![message.into()])
            .map_err(|e| to_status(e))?;
        let application_data = match events.last().unwrap() {
            GroupEvent::ApplicationMessage(application_message) => application_message.message(),
            _ => {
                return Err(Status::aborted(
                    "the given ciphertext did not contain an applicatio message",
                ))
            }
        }
        .to_vec();

        Ok(Response::new(UnprotectResponse { application_data }))
        //Ok(Response::new(UnprotectResponse::default()))
    }

    async fn store_psk(
        &self,
        _request: tonic::Request<StorePskRequest>,
    ) -> Result<tonic::Response<StorePskResponse>, tonic::Status> {
        Ok(Response::new(StorePskResponse::default())) // TODO
    }

    async fn add_proposal(
        &self,
        request: tonic::Request<AddProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let add_proposal_request = request.get_ref();

        let group_id = self
            .state_id_map
            .lock()
            .unwrap()
            .get(&add_proposal_request.state_id)
            .ok_or(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "unknown state_id",
            ))?
            // Cloning here to avoid potential poisoning of the state_id_map.
            .clone();

        let key_package = KeyPackage::decode_detached(&add_proposal_request.key_package)
            .map_err(|_| Status::aborted("failed to deserialize key package"))?;
        let proposal = self
            .client
            .lock()
            .unwrap()
            .propose_add_members(&group_id, &[key_package])
            .map_err(|e| to_status(e))?
            .first()
            .unwrap()
            .tls_serialize_detached()
            .map_err(|_| Status::aborted("failed to serialize proposal"))?;

        Ok(Response::new(ProposalResponse { proposal }))
    }

    async fn update_proposal(
        &self,
        request: tonic::Request<UpdateProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let update_proposal_request = request.get_ref();

        let group_id = self
            .state_id_map
            .lock()
            .unwrap()
            .get(&update_proposal_request.state_id)
            .ok_or(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "unknown state_id",
            ))?
            // Cloning here to avoid potential poisoning of the state_id_map.
            .clone();

        let proposal = self
            .client
            .lock()
            .unwrap()
            .propose_self_update(&group_id, None)
            .map_err(|e| to_status(e))?
            .first()
            .unwrap()
            .tls_serialize_detached()
            .map_err(|_| Status::aborted("failed to serialize proposal"))?;

        Ok(Response::new(ProposalResponse { proposal }))
    }

    async fn remove_proposal(
        &self,
        request: tonic::Request<RemoveProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let remove_proposal_request = request.get_ref();

        let group_id = self
            .state_id_map
            .lock()
            .unwrap()
            .get(&remove_proposal_request.state_id)
            .ok_or(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "unknown state_id",
            ))?
            // Cloning here to avoid potential poisoning of the state_id_map.
            .clone();

        let proposal = self
            .client
            .lock()
            .unwrap()
            .propose_remove_members(&group_id, &[remove_proposal_request.removed as usize])
            .map_err(|e| to_status(e))?
            .first()
            .unwrap()
            .tls_serialize_detached()
            .map_err(|_| Status::aborted("failed to serialize proposal"))?;

        Ok(Response::new(ProposalResponse { proposal }))
    }

    async fn psk_proposal(
        &self,
        _request: tonic::Request<PskProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        Ok(Response::new(ProposalResponse::default())) // TODO
    }

    async fn re_init_proposal(
        &self,
        _request: tonic::Request<ReInitProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        Ok(Response::new(ProposalResponse::default())) // TODO
    }

    async fn app_ack_proposal(
        &self,
        _request: tonic::Request<AppAckProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        Ok(Response::new(ProposalResponse::default())) // TODO
    }

    async fn commit(
        &self,
        _request: tonic::Request<CommitRequest>,
    ) -> Result<tonic::Response<CommitResponse>, tonic::Status> {
        Ok(Response::new(CommitResponse::default())) // TODO
    }

    async fn handle_commit(
        &self,
        _request: tonic::Request<HandleCommitRequest>,
    ) -> Result<tonic::Response<HandleCommitResponse>, tonic::Status> {
        Ok(Response::new(HandleCommitResponse::default())) // TODO
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

    // XXX(RLB): There's probably a more direct way to do this than building a string and then
    // parsing it.
    let addr = format!("{}:{}", opts.host, opts.port).parse().unwrap();
    let mls_client_impl = MlsClientImpl::new();

    println!("Listening on {}", addr);

    Server::builder()
        .add_service(MlsClientServer::new(mls_client_impl))
        .serve(addr)
        .await?;

    Ok(())
}
