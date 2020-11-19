//! The main Delivery Service (DS).
//!
//! This is a minimal implementation of 2.3. Delivery Service in [The MLS Architecture](https://messaginglayersecurity.rocks/mls-architecture/draft-ietf-mls-architecture.html).
//!
//! This is a very basic delivery service that allows to register clients and
//! send messages to other registered clients.
//! Note that there are a lot of limitations to this service
//! * no persistence layer such that all information gets lost when the process shuts down.
//! * no authentication for clients
//!
//! **DON'T EXPECT ANY SECURITY OR PRIVACY FROM THIS!**
//!
//! The server always listens on localhost and should be run behind a TLS server
//! if accessible on the public internet.
//!
//! The DS returns a list of messages queued for the client in all groups they
//! are part of.

use actix_web::{
    body::Body, get, post, web, web::Bytes, web::Payload, App, HttpRequest, HttpServer, Responder,
};
use clap::App as ClapApp;
use futures_util::StreamExt;
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::sync::Mutex;

pub(crate) use openmls::prelude::*;

#[cfg(test)]
mod test;

// === DS Server State ===

// The client identity is a hash of the identity used for message delivery.
type KeyPackageHash = Vec<u8>;

#[derive(Default, Debug)]
struct DsData {
    // (ClientName, ClientInfo)
    clients: HashMap<String, ClientInfo>,
}

#[derive(Debug, Default, Clone, PartialEq)]
struct ClientKeyPackages(Vec<(KeyPackageHash, KeyPackage)>);

impl Codec for ClientKeyPackages {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (self.0.len() as u32).encode(buffer)?;
        for (hash, key_package) in self.0.iter() {
            encode_vec(VecSize::VecU16, buffer, &hash)?;
            key_package.encode(buffer)?;
        }
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let length = u32::decode(cursor)?;
        let mut key_packages = Vec::with_capacity(length as usize);
        for _ in 0..length {
            let hash = decode_vec(VecSize::VecU16, cursor)?;
            let key_package = KeyPackage::decode(cursor)?;
            key_packages.push((hash, key_package));
        }
        Ok(ClientKeyPackages(key_packages))
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct ClientInfo {
    client_name: String,
    key_packages: ClientKeyPackages,
    msgs: Vec<MLSMessage>,
    welcome_queue: Vec<Welcome>,
}

impl Codec for ClientInfo {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        let client_name_bytes = self.client_name.as_bytes();
        (client_name_bytes.len() as u16).encode(buffer)?;
        buffer.extend_from_slice(&client_name_bytes);

        (self.key_packages.0.len() as u16).encode(buffer)?;
        for key_package in self.key_packages.0.iter() {
            encode_vec(VecSize::VecU16, buffer, &key_package.0)?;
            key_package.1.encode(buffer)?;
        }
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let client_name_length = u16::decode(cursor)?;
        let client_name = std::str::from_utf8(cursor.consume(client_name_length.into())?)
            .unwrap()
            .to_string();

        let mut key_packages = Vec::new();
        let num_key_packages = u16::decode(cursor)?;
        for _ in 0..num_key_packages {
            let hash = decode_vec(VecSize::VecU16, cursor)?;
            let key_package = KeyPackage::decode(cursor)?;
            key_packages.push((hash, key_package));
        }
        Ok(Self::new(client_name, key_packages))
    }
}

impl ClientInfo {
    #[cfg(test)]
    pub(crate) fn new(
        client_name: String,
        key_packages: Vec<(KeyPackageHash, KeyPackage)>,
    ) -> Self {
        Self {
            client_name,
            key_packages: ClientKeyPackages(key_packages),
            msgs: Vec::new(),
            welcome_queue: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    MLSMessage(MLSMessage),
    Welcome(Welcome),
}

#[derive(Debug, Clone, PartialEq)]
pub enum MLSMessage {
    MLSCiphertext(MLSCiphertext),
    MLSPlaintext(MLSPlaintext),
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum MessageType {
    MLSCiphertext = 0,
    MLSPlaintext = 1,
    Welcome = 2,
}

impl Codec for MessageType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let value = u8::decode(cursor)?;
        match value {
            0 => Ok(Self::MLSCiphertext),
            1 => Ok(Self::MLSPlaintext),
            2 => Ok(Self::Welcome),
            _ => Err(CodecError::DecodingError),
        }
    }
}

impl Codec for Message {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            Message::MLSMessage(m) => match m {
                MLSMessage::MLSCiphertext(m) => {
                    MessageType::MLSCiphertext.encode(buffer)?;
                    m.encode(buffer)?;
                }
                MLSMessage::MLSPlaintext(m) => {
                    MessageType::MLSPlaintext.encode(buffer)?;
                    m.encode(buffer)?;
                }
            },
            Message::Welcome(m) => {
                MessageType::Welcome.encode(buffer)?;
                m.encode(buffer)?;
            }
        }
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let msg_type = MessageType::decode(cursor)?;
        let msg = match msg_type {
            MessageType::MLSCiphertext => {
                Message::MLSMessage(MLSMessage::MLSCiphertext(MLSCiphertext::decode(cursor)?))
            }
            MessageType::MLSPlaintext => {
                Message::MLSMessage(MLSMessage::MLSPlaintext(MLSPlaintext::decode(cursor)?))
            }
            MessageType::Welcome => Message::Welcome(Welcome::decode(cursor)?),
        };
        Ok(msg)
    }
}

/// An MLS group message.
/// This is an `MLSMessage` plus the list of recipients.
#[derive(Debug)]
pub struct GroupMessage {
    msg: MLSMessage,
    recipients: Vec<String>,
}

impl GroupMessage {
    pub fn new(msg: MLSMessage, recipients: &[String]) -> Self {
        Self {
            msg,
            recipients: recipients.to_vec(),
        }
    }
}

impl Codec for GroupMessage {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        match &self.msg {
            MLSMessage::MLSCiphertext(m) => {
                MessageType::MLSCiphertext.encode(buffer)?;
                m.encode(buffer)?;
            }
            MLSMessage::MLSPlaintext(m) => {
                MessageType::MLSPlaintext.encode(buffer)?;
                m.encode(buffer)?;
            }
        }
        (self.recipients.len() as u16).encode(buffer)?;
        for recipient in self.recipients.iter() {
            let recipient_bytes = recipient.as_bytes();
            (recipient_bytes.len() as u16).encode(buffer)?;
            buffer.extend_from_slice(&recipient_bytes);
        }
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let msg_type = MessageType::decode(cursor)?;
        let msg = match msg_type {
            MessageType::MLSCiphertext => MLSMessage::MLSCiphertext(MLSCiphertext::decode(cursor)?),
            MessageType::MLSPlaintext => MLSMessage::MLSPlaintext(MLSPlaintext::decode(cursor)?),
            _ => return Err(CodecError::DecodingError),
        };

        let num_clients = u16::decode(cursor)?;
        let mut recipients = Vec::new();
        for _ in 0..num_clients {
            let client_name_length = u16::decode(cursor)?;
            let client_name = std::str::from_utf8(cursor.consume(client_name_length.into())?)
                .unwrap()
                .to_string();
            recipients.push(client_name);
        }
        Ok(Self { msg, recipients })
    }
}

// === API ===

#[post("/clients/register")]
async fn register_client(mut body: Payload, data: web::Data<Mutex<DsData>>) -> impl Responder {
    let mut data = data.lock().unwrap();

    let mut bytes = web::BytesMut::new();
    while let Some(item) = body.next().await {
        bytes.extend_from_slice(&item.unwrap());
    }
    let info = ClientInfo::decode(&mut Cursor::new(&bytes)).unwrap();
    let old = data.clients.insert(info.client_name.clone(), info.clone());
    assert!(old.is_none());

    actix_web::HttpResponse::Ok().body(format!("Welcome {}!\n", info.client_name))
}

#[get("/clients/list")]
async fn list_clients(_req: HttpRequest, data: web::Data<Mutex<DsData>>) -> impl Responder {
    let data = data.lock().unwrap();
    actix_web::HttpResponse::Ok().body(format!(
        "I know these clients {:?}!\n",
        &data.deref().clients.keys()
    ))
}

#[get("/clients/get/{name}")]
async fn get_client(
    web::Path(name): web::Path<String>,
    data: web::Data<Mutex<DsData>>,
) -> impl Responder {
    let data = data.lock().unwrap();
    let client = data.clients.get(&name).unwrap();
    actix_web::HttpResponse::Ok().body(Body::Bytes(Bytes::copy_from_slice(
        &client.key_packages.encode_detached().unwrap(),
    )))
}

#[post("/send/welcome")]
async fn send_welcome(mut body: Payload, data: web::Data<Mutex<DsData>>) -> impl Responder {
    let mut data = data.lock().unwrap();

    let mut bytes = web::BytesMut::new();
    while let Some(item) = body.next().await {
        bytes.extend_from_slice(&item.unwrap());
    }
    let welcome_msg = Welcome::decode(&mut Cursor::new(&bytes)).unwrap();

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

/// Takes a `GroupMessage`
#[post("/send/message")]
async fn msg_send(mut body: Payload, data: web::Data<Mutex<DsData>>) -> impl Responder {
    let mut data = data.lock().unwrap();
    let data = data.deref_mut();

    let mut bytes = web::BytesMut::new();
    while let Some(item) = body.next().await {
        bytes.extend_from_slice(&item.unwrap());
    }
    let group_msg = GroupMessage::decode(&mut Cursor::new(&bytes)).unwrap();
    println!("MLS msg: {:?}", group_msg);

    for recipient in group_msg.recipients.iter() {
        let client = match data.clients.get_mut(recipient) {
            Some(client) => client,
            None => return actix_web::HttpResponse::NotFound().finish(),
        };
        client.msgs.push(group_msg.msg.clone());
    }
    actix_web::HttpResponse::Ok().finish()
}

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
        .map(|m| Message::Welcome(m))
        .collect();
    out.append(&mut welcomes);
    let mut msgs: Vec<Message> = client
        .msgs
        .drain(..)
        .map(|m| Message::MLSMessage(m))
        .collect();
    out.append(&mut msgs);

    let mut out_bytes = Vec::new();
    if encode_vec(VecSize::VecU16, &mut out_bytes, &out).is_err() {
        return actix_web::HttpResponse::InternalServerError().finish();
    };

    actix_web::HttpResponse::Ok().body(Body::Bytes(Bytes::copy_from_slice(&out_bytes)))
}

// === Main function driving the DS ===

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Configure App and command line arguments.
    let matches = ClapApp::new("MLS DS")
        .version("0.0.1")
        .author("Wire")
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
            .service(get_client)
            .service(send_welcome)
            .service(msg_recv)
            .service(msg_send)
    })
    .bind(addr)?
    .run()
    .await
}
