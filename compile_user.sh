#!/bin/sh

script_path="$(dirname $0)"
CC="clang-8"

"$CC" -nostdlib -Wl,-T "${script_path}/user.ld" -o "$2" -I "${script_path}/include.user" -O2 "$1" --static -lc -Wl,-N