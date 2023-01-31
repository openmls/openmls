use tls_codec::{Deserialize, TlsVecU16, TlsVecU32};
use url::Url;

use super::{
    networking::{get, post},
    user::User,
};

use ds_lib::*;
use openmls::{prelude::*, prelude_test::MlsMessageOut};

pub struct Backend {
    ds_url: Url,
}

impl Backend {
    /// Register a new client with the server.
    pub fn register_client(&self, user: &User) -> Result<String, String> {
        let mut url = self.ds_url.clone();
        url.set_path("/clients/register");

        let client_info = ClientInfo::new(user.username.clone(), user.key_packages());
        let response = post(&url, &client_info)?;

        Ok(String::from_utf8(response).unwrap())
    }

    /// Get a list of all clients with name, ID, and key packages from the
    /// server.
    pub fn list_clients(&self) -> Result<Vec<ClientInfo>, String> {
        let mut url = self.ds_url.clone();
        url.set_path("/clients/list");

        let response = get(&url)?;
        match TlsVecU32::<ClientInfo>::tls_deserialize(&mut response.as_slice()) {
            Ok(clients) => Ok(clients.into()),
            Err(e) => Err(format!("Error decoding server response: {e:?}")),
        }
    }

    /// Get a list of key packages for a client.
    pub fn get_client(&self, client_id: &[u8]) -> Result<ClientKeyPackages, String> {
        let mut url = self.ds_url.clone();
        let path = "/clients/key_packages/".to_string()
            + &base64::encode_config(client_id, base64::URL_SAFE);
        url.set_path(&path);

        let response = get(&url)?;
        match ClientKeyPackages::tls_deserialize(&mut response.as_slice()) {
            Ok(ckp) => Ok(ckp),
            Err(e) => Err(format!("Error decoding server response: {e:?}")),
        }
    }

    /// Send a welcome message.
    pub fn send_welcome(&self, welcome_msg: &MlsMessageOut) -> Result<(), String> {
        let mut url = self.ds_url.clone();
        url.set_path("/send/welcome");

        // The response should be empty.
        let _response = post(&url, welcome_msg)?;
        Ok(())
    }

    /// Send a group message.
    pub fn send_msg(&self, group_msg: &GroupMessage) -> Result<(), String> {
        let mut url = self.ds_url.clone();
        url.set_path("/send/message");

        // The response should be empty.
        let _response = post(&url, group_msg)?;
        Ok(())
    }

    /// Get a list of all new messages for the user.
    pub fn recv_msgs(&self, user: &User) -> Result<Vec<MlsMessageIn>, String> {
        let mut url = self.ds_url.clone();
        let path = "/recv/".to_string()
            + &base64::encode_config(user.identity.borrow().identity(), base64::URL_SAFE);
        url.set_path(&path);

        let response = get(&url)?;
        match TlsVecU16::<MlsMessageIn>::tls_deserialize(&mut response.as_slice()) {
            Ok(r) => Ok(r.into()),
            Err(e) => Err(format!("Invalid message list: {e:?}")),
        }
    }

    /// Reset the DS.
    pub fn reset_server(&self) {
        let mut url = self.ds_url.clone();
        url.set_path("reset");
        get(&url).unwrap();
    }
}

impl Default for Backend {
    fn default() -> Self {
        Self {
            // There's a public DS at https://mls.franziskuskiefer.de
            ds_url: Url::parse("http://localhost:8080").unwrap(),
        }
    }
}
