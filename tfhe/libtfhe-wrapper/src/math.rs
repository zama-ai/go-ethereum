use crate::error::{handle_c_error_binary, RustError};
use crate::keys::SERVER_KEY;
use crate::memory::{ByteSliceView, UnmanagedVector};
use std::panic::catch_unwind;
use tfhe::prelude::*;
use tfhe::FheUint8;

pub enum Op {
    Add,
    Sub,
    Mul,
    Lt,
    Lte,
}

pub fn op_uint8(
    lhs: ByteSliceView,
    rhs: ByteSliceView,
    operation: Op,
    err_msg: Option<&mut UnmanagedVector>,
) -> UnmanagedVector {
    let server_key_guard = SERVER_KEY.lock().unwrap();

    let r: Result<Vec<u8>, RustError> = catch_unwind(|| {
        match *server_key_guard {
            true => {}
            false => panic!("Server key not set"), // Return an error or handle this case appropriately.
        };

        let num1 = bincode::deserialize::<FheUint8>(lhs.read().unwrap()).unwrap();
        let num2 = bincode::deserialize::<FheUint8>(rhs.read().unwrap()).unwrap();

        let result = match operation {
            Op::Add => num1 + num2,
            Op::Sub => num1 - num2,
            Op::Mul => num1 * num2,
            Op::Lt => num1.lt(num2),
            Op::Lte => num1.le(num2),
        };

        let r = bincode::serialize(&result).unwrap();

        r
    })
    .map_err(|err| {
        eprintln!("Panic in op_uint8: {:?}", err);
        RustError::generic_error("lol")
    });

    let result = handle_c_error_binary(r, err_msg);
    UnmanagedVector::new(Some(result))
}
