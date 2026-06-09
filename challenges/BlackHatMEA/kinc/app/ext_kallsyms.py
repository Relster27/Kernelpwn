#!/usr/bin/env python3

from pwn import *

PROMPT = b"~ # "

# Start process
p = process("./run")
p.recvuntil(PROMPT)

# Read symbols
p.sendline(b"cat /proc/kallsyms")
p.recvline() # Discard command echo
syms = p.recvuntil(PROMPT, drop=True)
print(f"test")
# Write symbols
with open("kallsyms", "wb") as f:
    f.write(syms)

print(f"testlast")
