//! # The OpenMLS Delivery Service (DS).
//!
//! This is a minimal implementation of 2.3. Delivery Service in
//! [The MLS Architecture](https://messaginglayersecurity.rocks/mls-architecture/draft-ietf-mls-architecture.html).
//! It is used for end-to-end testing of OpenMLS and can be used by other
//! implementations. However it should never be used in any sort of production
//! environment.
//!
//! Because the infrastructure description doesn't give a lot of guidelines on
//! the design of the DS we take a couple of deliberate design decisions here:
//! * The DS does not know about groups.
//! * Clients have to send a list of clients (group members) along with each
//!   message for the DS to know where to send the message.
//! * The DS stores and delivers key packages.
//!
//! This is a very basic delivery service that allows to register clients and
//! send messages to MLS groups.
//! Note that there are a lot of limitations to this service:
//! * No persistence layer such that all information gets lost when the process
//!   shuts down.
//! * No authentication for clients.
//! * Key packages can't be updated, changed or deleted at the moment.
//! * Messages lost in transit are gone.
//!
//! **⚠️ DON'T EXPECT ANY SECURITY OR PRIVACY FROM THIS!**
//!
//! The server always listens on localhost and should be run behind a TLS server
//! if accessible on the public internet.
//!
//! The DS returns a list of messages queued for the client in all groups they
//! are part of.

use actix_web::{
    body::Body, get, post, web, web::Payload, App, HttpRequest, HttpServer, Responder,
};
use clap::App as ClapApp;
use futures_util::StreamExt;
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::sync::Mutex;

use ds_lib::*;
use openmls::prelude::*;

#[cfg(test)]
mod test;

/// The DS state.
/// It holds a list of clients and their information.
#[derive(Default, Debug)]
pub struct DsData {
    // (ClientName, ClientInfo)
    clients: HashMap<String, ClientInfo>,

    // (group_id, epoch)
    groups: HashMap<Vec<u8>, u64>,
}

// === API ===

/// Registering a new client takes a serialised `ClientInfo` object and returns
/// a simple "Welcome {client name}" on success.
/// An HTTP conflict (409) is returned if a client with this name exists already.
#[post("/clients/register")]
async fn register_client(mut body: Payload, data: web::Data<Mutex<DsData>>) -> impl Responder {
    let mut bytes = web::BytesMut::new();
    while let Some(item) = body.next().await {
        bytes.extend_from_slice(&item.unwrap());
    }
    let info = ClientInfo::decode(&mut Cursor::new(&bytes)).unwrap();

    let mut data = data.lock().unwrap();
    let old = data.clients.insert(info.client_name.clone(), info.clone());
    if old.is_some() {
        return actix_web::HttpResponse::Conflict().finish();
    }

    actix_web::HttpResponse::Ok().body(format!("Welcome {}!\n", info.client_name))
}

/// Returns a list of clients.
/// This is informational only right now and returns the list of client names
/// as JSON (binary string).
#[get("/clients/list")]
async fn list_clients(_req: HttpRequest, data: web::Data<Mutex<DsData>>) -> impl Responder {
    let data = data.lock().unwrap();
    let clients: Vec<&String> = data.deref().clients.keys().collect();
    actix_web::HttpResponse::Ok().body(Body::from_slice(
        web::Json(serde_json::to_string(&clients).unwrap())
            .to_string()
            .as_bytes(),
    ))
}

/// Get the list of key packages for a given client `{name}`.
/// This returns a serialised vector of `ClientKeyPackages` (see the `ds-lib` for
/// details).
#[get("/clients/key_packages/{name}")]
async fn get_key_packages(
    web::Path(name): web::Path<String>,
    data: web::Data<Mutex<DsData>>,
) -> impl Responder {
    let data = data.lock().unwrap();
    let client = data.clients.get(&name).unwrap();
    actix_web::HttpResponse::Ok().body(Body::from_slice(
        &client.key_packages.encode_detached().unwrap(),
    ))
}

/// Send a welcome message to a client.
/// This takes a serialised `Welcome` message and stores the message for all
/// clients in the welcome message.
#[post("/send/welcome")]
async fn send_welcome(mut body: Payload, data: web::Data<Mutex<DsData>>) -> impl Responder {
    let mut bytes = web::BytesMut::new();
    while let Some(item) = body.next().await {
        bytes.extend_from_slice(&item.unwrap());
    }
    let welcome_msg = Welcome::decode(&mut Cursor::new(&bytes)).unwrap();

    let mut data = data.lock().unwrap();
    for secret in welcome_msg.get_secrets_ref().iter() {
        let key_package_hash = &secret.key_package_hash;
        for (_client_name, client) in data.clients.iter_mut() {
            for (client_hash, _) in client.key_packages.0.iter() {
                if client_hash == key_package_hash {
                    client.welcome_queue.push(welcome_msg.clone());
                }
            }
        }
    }
    actix_web::HttpResponse::Ok().finish()
}

/// Send an MLS message to a set of clients (group).
/// This takes a serialised `GroupMessage` and stores the message for each client
/// in the recipient list.
/// If a handshake message is sent with an epoch smaller or equal to another
/// handshake message this DS has seen, a 409 is returned and the message is not
/// processed.
#[post("/send/message")]
async fn msg_send(mut body: Payload, data: web::Data<Mutex<DsData>>) -> impl Responder {
    let mut bytes = web::BytesMut::new();
    while let Some(item) = body.next().await {
        bytes.extend_from_slice(&item.unwrap());
    }
    let group_msg = GroupMessage::decode(&mut Cursor::new(&bytes)).unwrap();

    let mut data = data.lock().unwrap();

    // Reject any handshake message that has an earlier epoch than the one know
    // about.
    // XXX: There's no test for this block in here right now because it's pretty
    //      painful to test in the current setting. This should get tested through
    //      the client and maybe later with the managed API.
    if group_msg.msg.is_handshake_message() {
        let epoch = group_msg.epoch();
        let group_id = group_msg.group_id();
        if let Some(&group_epoch) = data.groups.get(&group_id) {
            if group_epoch >= epoch {
                return actix_web::HttpResponse::Conflict().finish();
            }
            // Update server state to the latest epoch.
            let old_value = data.groups.insert(group_id, epoch);
            if old_value.is_none() {
                return actix_web::HttpResponse::InternalServerError().finish();
            }
        } else {
            // We haven't seen this group_id yet. Store it.
            let old_value = data.groups.insert(group_id, epoch);
            if old_value.is_some() {
                return actix_web::HttpResponse::InternalServerError().finish();
            }
        }
    }

    for recipient in group_msg.recipients.iter() {
        let client = match data.clients.get_mut(recipient) {
            Some(client) => client,
            None => return actix_web::HttpResponse::NotFound().finish(),
        };
        client.msgs.push(group_msg.msg.clone());
    }
    actix_web::HttpResponse::Ok().finish()
}

/// Receive all messages stored for the client `{name}`.
/// This returns a serialised vector of `Message`s (see the `ds-lib` for details)
/// the DS has stored for the given client.
/// The messages are deleted on the DS when sent out.
#[get("/recv/{name}")]
async fn msg_recv(
    web::Path(name): web::Path<String>,
    data: web::Data<Mutex<DsData>>,
) -> impl Responder {
    let mut data = data.lock().unwrap();
    let data = data.deref_mut();

    let client = match data.clients.get_mut(&name) {
        Some(client) => client,
        None => return actix_web::HttpResponse::NotFound().finish(),
    };

    let mut out: Vec<Message> = Vec::new();
    let mut welcomes: Vec<Message> = client
        .welcome_queue
        .drain(..)
        .map(Message::Welcome)
        .collect();
    out.append(&mut welcomes);
    let mut msgs: Vec<Message> = client.msgs.drain(..).map(Message::MLSMessage).collect();
    out.append(&mut msgs);

    let mut out_bytes = Vec::new();
    if encode_vec(VecSize::VecU16, &mut out_bytes, &out).is_err() {
        return actix_web::HttpResponse::InternalServerError().finish();
    };

    actix_web::HttpResponse::Ok().body(Body::from_slice(&out_bytes))
}

// === Main function driving the DS ===

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Configure App and command line arguments.
    let matches = ClapApp::new("OpenMLS DS")
        .version("0.1.0")
        .author("OpenMLS Developers")
        .about("PoC MLS Delivery Service")
        .arg("-p, --port=[NUMBER] 'Sets a custom port number'")
        .get_matches();

    // The data this app operates on.
    let data = web::Data::new(Mutex::new(DsData::default()));

    // Set default port or use port provided on the command line.
    let port = if let Some(p) = matches.value_of("port") {
        p.parse::<u16>().unwrap()
    } else {
        8080
    };
    let ip = "127.0.0.1";
    let addr = format!("{}:{}", ip, port.to_string());
    println!("Listening on: {}", addr);

    // Start the server.
    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .service(register_client)
            .service(list_clients)
            .service(get_key_packages)
            .service(send_welcome)
            .service(msg_recv)
            .service(msg_send)
    })
    .bind(addr)?
    .run()
    .await
}
