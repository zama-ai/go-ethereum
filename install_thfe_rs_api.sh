#!/bin/bash

git clone https://github.com/zama-ai/tfhe-rs.git
mkdir -p core/vm/lib
cd tfhe-rs
make build_c_api
cp target/release/libtfhe.* ../core/vm/lib
cp target/release/tfhe.h ../core/vm
