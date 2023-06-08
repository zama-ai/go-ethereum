use std::panic::{AssertUnwindSafe, catch_unwind};
use tfhe::{ServerKey, ClientKey};

use crate::keys::{SERVER_KEY, CLIENT_KEY};

use bincode2 as bincode;
use serde::Serialize;
use tfhe::FheUint8;
use tfhe::prelude::FheEncrypt;

use crate::error::{handle_c_error_binary, handle_c_error_default, handle_c_error_ptr, RustError};

use crate::memory::{ByteSliceView, UnmanagedVector};

#[repr(C)]
pub struct c_void {}

#[no_mangle]
pub unsafe extern "C" fn deserialize_server_key(key: ByteSliceView, err_msg: Option<&mut UnmanagedVector>) -> bool {
    let r: Result<bool, RustError> = catch_unwind(|| {
        let maybe_key_deserialized = bincode::deserialize::<ServerKey>(key.read().unwrap()).unwrap();

        let mut server_key = SERVER_KEY.lock().unwrap();
        *server_key = Some(maybe_key_deserialized);

        true
    }).map_err(
        |err| {
            eprintln!("Panic in deserialize_server_key: {:?}", err);
            RustError::generic_error("lol")
        }
    );

    handle_c_error_default(r, err_msg) as bool
}

#[no_mangle]
pub unsafe extern "C" fn deserialize_client_key(key: ByteSliceView, err_msg: Option<&mut UnmanagedVector>) -> bool {
    let r: Result<bool, RustError> = catch_unwind(|| {
        let maybe_key_deserialized = bincode::deserialize::<ClientKey>(key.read().unwrap()).unwrap();

        let mut client_key = CLIENT_KEY.lock().unwrap();
        *client_key = Some(maybe_key_deserialized);

        true
    }).map_err(
        |err| {
            eprintln!("Panic in deserialize_client_key: {:?}", err);
            RustError::generic_error("lol")
        }
    );

    handle_c_error_default(r, err_msg) as bool
}

#[no_mangle]
pub unsafe extern "C" fn client_key_encrypt_fhe_uint8(msg: u64, err_msg: Option<&mut UnmanagedVector>) -> UnmanagedVector {
    let client_key_guard = CLIENT_KEY.lock().unwrap();
    
    let r: Result<Vec<u8>, RustError> = catch_unwind(|| {

        let client_key = match *client_key_guard {
            Some(ref ck) => ck,
            None => panic!("Client key not set"),  // Return an error or handle this case appropriately.
        };

        // option 2 is to pass pointers to these encrypted integers, but I kind of hate that
        // though the performance overhead might be pretty big - todo: check that
        let enc = FheUint8::encrypt(msg as u8, client_key);

        let now = std::time::Instant::now();
        let r = bincode2::serialize(&enc).unwrap();
        let stop = now.elapsed().as_micros();

        println!("Serialize u8 took: {}us", stop);

        r
    }).map_err(|err| {
        eprintln!("Panic in deserialize_client_key: {:?}", err);
        RustError::generic_error("lol2")
    });

    let result = handle_c_error_binary(r, err_msg);
    UnmanagedVector::new(Some(result))

}

// #[no_mangle]
// pub unsafe extern "C" fn checked_set_server_key(sks: *mut c_void) {
//     let r = set_server_key(&*(sks as *mut ServerKey));
//     assert_eq!(r, 0);
// }
//
// #[no_mangle]
// pub unsafe extern "C" fn serialize_fhe_uint8(ct: *mut c_void, out: &mut Buffer) {
//     let r = FheUint8::serialize(&*(ct as *mut FheUint8), out);
//     assert_eq!(r, 0);
// }
//
// pub fn public_key_encrypt_fhe_uint32() {
//
// }
//
// pub fn public_key_encrypt_fhe_uint16() {
//
// }
//
// pub fn public_key_encrypt_fhe_uint8() {
//
// }
//
// pub fn client_key_encrypt_fhe_uint32() {
//
// }
//
// pub fn client_key_encrypt_fhe_uint16() {
//
// }
//
// pub fn client_key_encrypt_fhe_uint8() {
//
// }

// #[no_mangle]
// pub unsafe extern "C" fn decrypt_fhe_uint32(cks: *mut c_void, ct: *mut c_void) -> uint32_t {
//     let mut res: u32 = 0;
//     let r = FheUint32::decrypt(
//         &*(ct as *mut FheUint32),
//         &*(cks as *mut ClientKey),
//         &mut res,
//     );
//     assert_eq!(r, 0);
//     res
// }
//
// pub fn decrypt_fhe_uint16(cks: *mut c_void, ct: *mut c_void) -> uint32_t {
//     let mut res: u32 = 0;
//     let r = FheUint32::decrypt(
//         &*(ct as *mut FheUint32),
//         &*(cks as *mut ClientKey),
//         &mut res,
//     );
//     assert_eq!(r, 0);
//     res
// }

// pub fn decrypt_fhe_uint8(cks: *mut c_void, ct: *mut c_void) -> uint32_t {
//     let mut res: u32 = 0;
//     let r = FheUint32::decrypt(
//         &*(ct as *mut FheUint32),
//         &*(cks as *mut ClientKey),
//         &mut res,
//     );
//     assert_eq!(r, 0);
//     res
// }