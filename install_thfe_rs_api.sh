#!/bin/bash

git clone https://github.com/zama-ai/tfhe-rs.git
git checkout 189f02b696acad96ac18e6549714d64e4031a795
mkdir -p core/vm/lib
cd tfhe-rs
make build_c_api
cp target/release/libtfhe.* ../core/vm/lib
cp target/release/tfhe.h ../core/vm
