#!/bin/bash

git clone git@github.com:zama-ai/tfhe-rs.git
mkdir -p core/vm/lib
cd tfhe-rs
git checkout refactor/progressive-refactor
make build_c_api
cp target/release/libtfhe.* ../core/vm/lib
cp target/release/tfhe.h ../core/vm
