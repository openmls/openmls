//! This is a the OpenMLS client for the interop harness as described here:
//! https://github.com/mlswg/mls-implementations/tree/master/interop
//!
//! It is based on the Mock client written by Richard Barnes.

use clap::Clap;
use openmls::prelude::*;
use std::{
    collections::HashMap,
    convert::TryFrom,
    sync::{Arc, Mutex},
};
use tokio::{runtime::Runtime, task::*};
use tonic::{transport::Server, Request, Response, Status};
use utils::read;

use mls_client::mls_client_server::{MlsClient, MlsClientServer};
// TODO(RLB) Convert this back to more specific `use` directives
use mls_client::*;

mod utils;
pub mod mls_client {
    tonic::include_proto!("mls_client");
}

const IMPLEMENTATION_NAME: &str = "OpenMLS";
const SUPPORTED_CIPHERSUITES: [u32; 2] = Config::supported_ciphersuite_names();
const TEST_VECTOR: [u8; 4] = [0, 1, 2, 3];

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

struct Client<'client> {
    key_store: Arc<Mutex<KeyStore>>,
    groups: Arc<Mutex<Groups<'client>>>,
    credentials: HashMap<SignatureScheme, Credential>,
}

#[derive(Default)]
struct Groups<'group_states> {
    group_states: Arc<Mutex<HashMap<GroupId, ManagedGroup<'group_states>>>>,
}

pub struct MlsClientImpl<'client> {
    client: Arc<Mutex<Client<'client>>>,
}

impl<'client> MlsClient for MlsClientImpl<'client> {
    async fn name(&self, _request: Request<NameRequest>) -> Result<Response<NameResponse>, Status> {
        println!("Got Name request");

        let response = NameResponse {
            name: IMPLEMENTATION_NAME.to_string(),
        };
        Ok(Response::new(response))
    }

    fn supported_ciphersuites(
        &self,
        _request: tonic::Request<SupportedCiphersuitesRequest>,
    ) -> Result<tonic::Response<SupportedCiphersuitesResponse>, tonic::Status> {
        println!("Got SupportedCiphersuites request");

        let response = SupportedCiphersuitesResponse {
            ciphersuites: SUPPORTED_CIPHERSUITES.to_vec(),
        };

        Ok(Response::new(response))
    }

    fn generate_test_vector(
        &self,
        request: tonic::Request<GenerateTestVectorRequest>,
    ) -> Result<tonic::Response<GenerateTestVectorResponse>, tonic::Status> {
        println!("Got GenerateTestVector request");

        let obj = request.get_ref();
        // TODO: Generate the test vector here instead of reading it from file.
        let (type_msg, test_vector) = match TestVectorType::try_from(obj.test_vector_type) {
            Ok(TestVectorType::TreeMath) => {
                let kat_treemath = read("test_vectors/kat_treemath_openmls.json");
                ("Tree math", kat_treemath)
            }
            Ok(TestVectorType::Encryption) => {
                let kat_encryption = read("test_vectors/kat_encryption_openmls.json");
                ("Encryption", kat_encryption)
            }
            Ok(TestVectorType::KeySchedule) => {
                let kat_key_schedule = read("test_vectors/kat_key_schedule_openmls.json");
                ("Key Schedule", kat_key_schedule)
            }
            Ok(TestVectorType::Transcript) => {
                let kat_transcript = read("test_vectors/kat_transcripts_openmls.json");
                ("Key Schedule", kat_transcript)
            }
            //Ok(TestVectorType::Treekem) => ("TreeKEM", vec![]),
            Ok(TestVectorType::Treekem) => {
                ("TreeKEM", Vec::new())
                //return Err(tonic::Status::new(
                //    tonic::Code::InvalidArgument,
                //    "TreeKEM test vector generation not supported yet.",
                //));
            }
            Ok(TestVectorType::Messages) => {
                ("Messages", Vec::new())
                //return Err(tonic::Status::new(
                //    tonic::Code::InvalidArgument,
                //    "Messages test vector generation not supported yet.",
                //));
            }
            Err(_) => {
                return Err(tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "Invalid test vector type",
                ));
            }
        };
        println!("{} test vector request", type_msg);

        let response = GenerateTestVectorResponse {
            test_vector: TEST_VECTOR.to_vec(),
        };

        Ok(Response::new(response))
    }

    fn verify_test_vector(
        &self,
        request: tonic::Request<VerifyTestVectorRequest>,
    ) -> Result<tonic::Response<VerifyTestVectorResponse>, tonic::Status> {
        println!("Got VerifyTestVector request");

        let obj = request.get_ref();
        let type_msg = match TestVectorType::try_from(obj.test_vector_type) {
            Ok(TestVectorType::TreeMath) => ("Tree math"),
            Ok(TestVectorType::Encryption) => "Encryption",
            Ok(TestVectorType::KeySchedule) => "Key Schedule",
            Ok(TestVectorType::Transcript) => "Transcript",
            Ok(TestVectorType::Treekem) => "TreeKEM",
            Ok(TestVectorType::Messages) => "Messages",
            Err(_) => {
                return Err(tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "Invalid test vector type",
                ));
            }
        };
        println!("{} test vector request", type_msg);

        // TODO: Extract "run test vector" from tests and run it here.
        if (obj.test_vector != TEST_VECTOR) {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "Invalid test vector",
            ));
        }

        Ok(Response::new(VerifyTestVectorResponse::default()))
    }

    fn create_group(
        &self,
        _request: tonic::Request<CreateGroupRequest>,
    ) -> Result<tonic::Response<CreateGroupResponse>, tonic::Status> {
        Ok(Response::new(CreateGroupResponse::default())) // TODO
    }

    fn create_key_package(
        &self,
        _request: tonic::Request<CreateKeyPackageRequest>,
    ) -> Result<tonic::Response<CreateKeyPackageResponse>, tonic::Status> {
        Ok(Response::new(CreateKeyPackageResponse::default())) // TODO
    }

    fn join_group(
        &self,
        _request: tonic::Request<JoinGroupRequest>,
    ) -> Result<tonic::Response<JoinGroupResponse>, tonic::Status> {
        Ok(Response::new(JoinGroupResponse::default())) // TODO
    }

    fn external_join(
        &self,
        _request: tonic::Request<ExternalJoinRequest>,
    ) -> Result<tonic::Response<ExternalJoinResponse>, tonic::Status> {
        Ok(Response::new(ExternalJoinResponse::default())) // TODO
    }

    fn public_group_state(
        &self,
        _request: tonic::Request<PublicGroupStateRequest>,
    ) -> Result<tonic::Response<PublicGroupStateResponse>, tonic::Status> {
        Ok(Response::new(PublicGroupStateResponse::default())) // TODO
    }

    fn state_auth(
        &self,
        _request: tonic::Request<StateAuthRequest>,
    ) -> Result<tonic::Response<StateAuthResponse>, tonic::Status> {
        Ok(Response::new(StateAuthResponse::default())) // TODO
    }

    fn export(
        &self,
        _request: tonic::Request<ExportRequest>,
    ) -> Result<tonic::Response<ExportResponse>, tonic::Status> {
        Ok(Response::new(ExportResponse::default())) // TODO
    }

    fn protect(
        &self,
        _request: tonic::Request<ProtectRequest>,
    ) -> Result<tonic::Response<ProtectResponse>, tonic::Status> {
        Ok(Response::new(ProtectResponse::default())) // TODO
    }

    fn unprotect(
        &self,
        _request: tonic::Request<UnprotectRequest>,
    ) -> Result<tonic::Response<UnprotectResponse>, tonic::Status> {
        Ok(Response::new(UnprotectResponse::default())) // TODO
    }

    fn store_psk(
        &self,
        _request: tonic::Request<StorePskRequest>,
    ) -> Result<tonic::Response<StorePskResponse>, tonic::Status> {
        Ok(Response::new(StorePskResponse::default())) // TODO
    }

    fn add_proposal(
        &self,
        _request: tonic::Request<AddProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        Ok(Response::new(ProposalResponse::default())) // TODO
    }

    fn update_proposal(
        &self,
        _request: tonic::Request<UpdateProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        Ok(Response::new(ProposalResponse::default())) // TODO
    }

    fn remove_proposal(
        &self,
        _request: tonic::Request<RemoveProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        Ok(Response::new(ProposalResponse::default())) // TODO
    }

    fn psk_proposal(
        &self,
        _request: tonic::Request<PskProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        Ok(Response::new(ProposalResponse::default())) // TODO
    }

    fn re_init_proposal(
        &self,
        _request: tonic::Request<ReInitProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        Ok(Response::new(ProposalResponse::default())) // TODO
    }

    fn app_ack_proposal(
        &self,
        _request: tonic::Request<AppAckProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        Ok(Response::new(ProposalResponse::default())) // TODO
    }

    fn commit(
        &self,
        _request: tonic::Request<CommitRequest>,
    ) -> Result<tonic::Response<CommitResponse>, tonic::Status> {
        Ok(Response::new(CommitResponse::default())) // TODO
    }

    fn handle_commit(
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = Opts::parse();

    // XXX(RLB): There's probably a more direct way to do this than building a string and then
    // parsing it.
    let addr = format!("{}:{}", opts.host, opts.port).parse().unwrap();
    let mls_client_impl = MlsClientImpl::new();

    println!("Listening on {}", addr);

    use tokio::task;

    let mut runtime = Runtime::new().unwrap();
    let local = task::LocalSet::new();
    let server = Server::builder();

    // Run the local task group.
    local.block_on(&mut runtime, async move {
        task::spawn_local(async move {
            let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
            let incoming = listener.incoming;
            Server::builder()
                .add_service(MlsClientServer::new(mls_client_impl))
                .serve_with_incoming(incoming)
                .await
        });
    });

    Ok(())
}
