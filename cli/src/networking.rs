use ds_lib::messages::AuthToken;
use reqwest::{self, blocking::Client, StatusCode};
use url::Url;

use openmls::prelude::tls_codec::Serialize;

// TODO: return objects not bytes.

pub fn post(url: &Url, msg: &impl Serialize) -> Result<Vec<u8>, String> {
    let serialized_msg = msg.tls_serialize_detached().unwrap();
    log::debug!("Post {url:?}");
    log::trace!("Payload: {serialized_msg:?}");
    let client = Client::new();
    let response = client.post(url.to_string()).body(serialized_msg).send();
    if let Ok(r) = response {
        if r.status() != StatusCode::OK {
            return Err(format!("Error status code {:?}", r.status()));
        }
        match r.bytes() {
            Ok(bytes) => Ok(bytes.as_ref().to_vec()),
            Err(e) => Err(format!("Error retrieving bytes from response: {e:?}")),
        }
    } else {
        Err(format!("ERROR: {:?}", response.err()))
    }
}

pub fn get(url: &Url) -> Result<Vec<u8>, String> {
    let auth_token_option: Option<&AuthToken> = None;
    get_internal(url, auth_token_option)
}

pub fn get_with_body(url: &Url, body: &impl Serialize) -> Result<Vec<u8>, String> {
    get_internal(url, Some(body))
}

fn get_internal(url: &Url, msg: Option<&impl Serialize>) -> Result<Vec<u8>, String> {
    log::debug!("Get {url:?}");
    let client = Client::new().get(url.to_string());
    let client = if let Some(msg) = msg {
        let serialized_msg = msg.tls_serialize_detached().unwrap();
        log::trace!("Payload: {serialized_msg:?}");
        client.body(serialized_msg)
    } else {
        client
    };
    let response = client.send();
    if let Ok(r) = response {
        if r.status() != StatusCode::OK {
            return Err(format!("Error status code {:?}", r.status()));
        }
        match r.bytes() {
            Ok(bytes) => Ok(bytes.as_ref().to_vec()),
            Err(e) => Err(format!("Error retrieving bytes from response: {e:?}")),
        }
    } else {
        Err(format!("ERROR: {:?}", response.err()))
    }
}
