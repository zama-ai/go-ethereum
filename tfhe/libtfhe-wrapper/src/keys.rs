use lazy_static::lazy_static;
use std::sync::{Arc, Mutex};
use tfhe::{ClientKey, ServerKey};

lazy_static! {
    pub static ref SERVER_KEY: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    pub static ref CLIENT_KEY: Arc<Mutex<Option<ClientKey>>> = Arc::new(Mutex::new(None));
}
