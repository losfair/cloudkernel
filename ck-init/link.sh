#!/bin/bash

script_path="$(dirname $0)"
script_path="$(realpath ${script_path})"

rm -rf "${script_path}/libck_init_a" 
mkdir "${script_path}/libck_init_a" || exit 1

pushd .
cd "${script_path}/libck_init_a"
ar x "${script_path}/target/x86_64-cloudkernel/release/libck_init.a" || exit 1
popd

ld -T "${script_path}/link.ld" -o "ck-init.elf" ${script_path}/libck_init_a/*.o || exit 1
python3 ${script_path}/../scripts/elf2ckm.py "ck-init.elf" "ck-init.ckm" || exit 1
