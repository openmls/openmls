use base64::Engine;
use tls_codec::{Deserialize, TlsVecU16, TlsVecU32};
use url::Url;

use crate::networking::get_with_body;

use super::{
    networking::{get, post},
    user::User,
};

use ds_lib::{
    messages::{
        AuthToken, PublishKeyPackagesRequest, RecvMessageRequest, RegisterClientRequest,
        RegisterClientSuccessResponse,
    },
    *,
};
use openmls::prelude::*;

pub struct Backend {
    ds_url: Url,
}

impl Backend {
    /// Register a new client with the server.
    pub fn register_client(
        &self,
        key_packages: Vec<(Vec<u8>, KeyPackage)>,
    ) -> Result<AuthToken, String> {
        let mut url = self.ds_url.clone();
        url.set_path("/clients/register");

        let key_packages = ClientKeyPackages(
            key_packages
                .into_iter()
                .map(|(b, kp)| (b.into(), KeyPackageIn::from(kp)))
                .collect::<Vec<_>>()
                .into(),
        );
        let request = RegisterClientRequest { key_packages };
        let response_bytes = post(&url, &request)?;
        let response =
            RegisterClientSuccessResponse::tls_deserialize(&mut response_bytes.as_slice())
                .map_err(|e| format!("Error decoding server response: {e:?}"))?;

        Ok(response.auth_token)
    }

    /// Get a list of all clients with name, ID, and key packages from the
    /// server.
    pub fn list_clients(&self) -> Result<Vec<Vec<u8>>, String> {
        let mut url = self.ds_url.clone();
        url.set_path("/clients/list");

        let response = get(&url)?;
        match TlsVecU32::<Vec<u8>>::tls_deserialize(&mut response.as_slice()) {
            Ok(clients) => Ok(clients.into()),
            Err(e) => Err(format!("Error decoding server response: {e:?}")),
        }
    }

    /// Get and reserve a key package for a client.
    pub fn consume_key_package(&self, client_id: &[u8]) -> Result<KeyPackageIn, String> {
        let mut url = self.ds_url.clone();
        let path = "/clients/key_package/".to_string()
            + &base64::engine::general_purpose::URL_SAFE.encode(client_id);
        url.set_path(&path);

        let response = get(&url)?;
        match KeyPackageIn::tls_deserialize(&mut response.as_slice()) {
            Ok(kp) => Ok(kp),
            Err(e) => Err(format!("Error decoding server response: {e:?}")),
        }
    }

    /// Publish client additional key packages
    pub fn publish_key_packages(&self, user: &User, ckp: ClientKeyPackages) -> Result<(), String> {
        let Some(auth_token) = user.auth_token() else {
            return Err("Please register user before publishing key packages".to_string());
        };
        let mut url = self.ds_url.clone();
        let path = "/clients/key_packages/".to_string()
            + &base64::engine::general_purpose::URL_SAFE.encode(user.identity.borrow().identity());
        url.set_path(&path);

        let request = PublishKeyPackagesRequest {
            key_packages: ckp,
            auth_token: auth_token.clone(),
        };

        // The response should be empty.
        let _response = post(&url, &request)?;
        Ok(())
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
        let Some(auth_token) = user.auth_token() else {
            return Err("Please register user before publishing key packages".to_string());
        };
        let mut url = self.ds_url.clone();
        let path = "/recv/".to_string()
            + &base64::engine::general_purpose::URL_SAFE.encode(user.identity.borrow().identity());
        url.set_path(&path);

        let request = RecvMessageRequest {
            auth_token: auth_token.clone(),
        };

        let response = get_with_body(&url, &request)?;
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
