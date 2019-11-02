#!/bin/bash

script_path="$(dirname $0)"
script_path="$(realpath ${script_path})"

rm -rf "${script_path}/libck_hal_a" 
mkdir "${script_path}/libck_hal_a" || exit 1

pushd .
cd "${script_path}/libck_hal_a"
ar x "${script_path}/target/x86_64-cloudkernel/release/libck_hal.a" || exit 1
popd

ld -T "${script_path}/link.ld" -o "ck-hal.elf" ${script_path}/libck_hal_a/*.o || exit 1
python3 ${script_path}/../scripts/elf2ckm.py "ck-hal.elf" "ck-hal.ckm" || exit 1
