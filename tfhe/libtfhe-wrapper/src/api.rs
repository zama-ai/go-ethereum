use crate::keys::{CLIENT_KEY, SERVER_KEY};
use std::panic::{catch_unwind, AssertUnwindSafe};
use tfhe::{set_server_key, ClientKey, FheUint8, ServerKey};

use serde::Serialize;
// use tfhe::c_api::high_level_api::integers::FheUint8;
use crate::math::op_uint8;
use tfhe::prelude::*;

use crate::error::{handle_c_error_binary, handle_c_error_default, handle_c_error_ptr, RustError};
use crate::math::Op;

use crate::memory::{ByteSliceView, UnmanagedVector};

#[repr(C)]
pub struct c_void {}

#[no_mangle]
pub unsafe extern "C" fn deserialize_server_key(
    key: ByteSliceView,
    err_msg: Option<&mut UnmanagedVector>,
) -> bool {
    let r: Result<bool, RustError> = catch_unwind(|| {
        let maybe_key_deserialized =
            bincode::deserialize::<ServerKey>(key.read().unwrap()).unwrap();

        set_server_key(maybe_key_deserialized);

        let mut server_key = SERVER_KEY.lock().unwrap();
        *server_key = true;

        true
    })
    .map_err(|err| {
        eprintln!("Panic in deserialize_server_key: {:?}", err);
        RustError::generic_error("lol")
    });

    handle_c_error_default(r, err_msg) as bool
}

#[no_mangle]
pub unsafe extern "C" fn deserialize_client_key(
    key: ByteSliceView,
    err_msg: Option<&mut UnmanagedVector>,
) -> bool {
    let r: Result<bool, RustError> = catch_unwind(|| {
        let maybe_key_deserialized =
            bincode::deserialize::<ClientKey>(key.read().unwrap()).unwrap();

        let mut client_key = CLIENT_KEY.lock().unwrap();
        *client_key = Some(maybe_key_deserialized);

        true
    })
    .map_err(|err| {
        eprintln!("Panic in deserialize_client_key: {:?}", err);
        RustError::generic_error("lol")
    });

    handle_c_error_default(r, err_msg) as bool
}

#[no_mangle]
pub unsafe extern "C" fn client_key_encrypt_fhe_uint8(
    msg: u64,
    err_msg: Option<&mut UnmanagedVector>,
) -> UnmanagedVector {
    let client_key_guard = CLIENT_KEY.lock().unwrap();

    let r: Result<Vec<u8>, RustError> = catch_unwind(|| {
        let client_key = match *client_key_guard {
            Some(ref ck) => ck,
            None => panic!("Client key not set"), // Return an error or handle this case appropriately.
        };

        let enc = FheUint8::encrypt(msg as u8, client_key);

        let now = std::time::Instant::now();
        let r = bincode::serialize(&enc).unwrap();
        let stop = now.elapsed().as_micros();

        println!("Serialize u8 took: {}us", stop);

        r
    })
    .map_err(|err| {
        eprintln!("Panic in client_key_encrypt_fhe_uint8: {:?}", err);
        RustError::generic_error("lol2")
    });

    let result = handle_c_error_binary(r, err_msg);
    UnmanagedVector::new(Some(result))
}

//itzik: This could be macroified, but for clarity and debuggability I prefer defining this outside
// a macro
#[no_mangle]
pub unsafe extern "C" fn add_uint8(
    lhs: ByteSliceView,
    rhs: ByteSliceView,
    err_msg: Option<&mut UnmanagedVector>,
) -> UnmanagedVector {
    op_uint8(lhs, rhs, Op::Add, err_msg)
}

#[no_mangle]
pub unsafe extern "C" fn sub_uint8(
    lhs: ByteSliceView,
    rhs: ByteSliceView,
    err_msg: Option<&mut UnmanagedVector>,
) -> UnmanagedVector {
    op_uint8(lhs, rhs, Op::Sub, err_msg)
}

#[no_mangle]
pub unsafe extern "C" fn mul_uint8(
    lhs: ByteSliceView,
    rhs: ByteSliceView,
    err_msg: Option<&mut UnmanagedVector>,
) -> UnmanagedVector {
    op_uint8(lhs, rhs, Op::Mul, err_msg)
}

#[no_mangle]
pub unsafe extern "C" fn lt_uint8(
    lhs: ByteSliceView,
    rhs: ByteSliceView,
    err_msg: Option<&mut UnmanagedVector>,
) -> UnmanagedVector {
    op_uint8(lhs, rhs, Op::Lt, err_msg)
}

#[no_mangle]
pub unsafe extern "C" fn lte_uint8(
    lhs: ByteSliceView,
    rhs: ByteSliceView,
    err_msg: Option<&mut UnmanagedVector>,
) -> UnmanagedVector {
    op_uint8(lhs, rhs, Op::Lte, err_msg)
}
