import sys
import subprocess
import re
import struct
import tempfile
import os

ELF64_BASE = int(os.getenv("ELF2CKM_ELF64_BASE", "0x60000000"), 16)

target = sys.argv[1]
outfile = sys.argv[2]

out = subprocess.check_output(["objdump", "-d", target]).decode("utf-8").split("\n")

metadata = b""

metadata += struct.pack("<I", 0xfac8912b)

prog = re.compile("([0-9a-f]+) <(.+)>:")
syms = []

for row in out:
    row = row.strip()
    m = prog.match(row)
    if m != None:
        s = (int(m[1], 16) - ELF64_BASE, m[2])
        print("Symbol: " + hex(s[0]) + " " + s[1])
        if s[1] == "_start":
            syms.append(s)

metadata += struct.pack("<I", len(syms))
for s in syms:
    enc = s[1].encode("utf-8")
    metadata += struct.pack("<QI", s[0], len(enc))
    metadata += enc

with tempfile.NamedTemporaryFile(mode = "rb") as f:
    ret = subprocess.call(["objcopy", "-O", "binary", target, f.name])
    if ret != 0:
        raise Exception("objcopy failed")
    result = metadata + f.read()
    with open(outfile, "w+b") as out:
        out.write(result)
