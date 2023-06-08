use lazy_static::lazy_static;
use tfhe::{ServerKey, ClientKey};
use std::sync::{Arc, Mutex};

lazy_static! {
    pub static ref SERVER_KEY: Arc<Mutex<Option<ServerKey>>> = Arc::new(Mutex::new(None));
    pub static ref CLIENT_KEY: Arc<Mutex<Option<ClientKey>>> = Arc::new(Mutex::new(None));
}
