#!/bin/bash

script_path="$(dirname $0)"
script_path="$(realpath ${script_path})"

RUST_TARGET_PATH="$script_path/../rust_target_spec" xargo build --release --target x86_64-cloudkernel
