#!/bin/bash

git clone https://github.com/zama-ai/tfhe-rs.git
git checkout 1d817c45d5234bcf33638406191b656998b30c2a
mkdir -p core/vm/lib
cd tfhe-rs
make build_c_api
cp target/release/libtfhe.* ../core/vm/lib
cp target/release/tfhe.h ../core/vm
