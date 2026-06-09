#!/usr/bin/env python3
import subprocess
import shutil
import os
from pwn import ELF
from tqdm import tqdm

CHUNK_SIZE    = 10000
KALLSYMS_FILE = "kallsyms"
VMLINUX_IN    = "vmlinux"
VMLINUX_OUT   = "vmlinux_with_syms"

def get_elf_sections(path):
    elf = ELF(path, checksec=False)
    sections = {}
    for section in elf.sections:
        name = section.name
        addr = section.header.sh_addr
        size = section.header.sh_size
        sections[name] = (addr, addr + size)
    return sections

def run_objcopy(args):
    objcopy_cmd = ["objcopy"]
    objcopy_cmd += args
    objcopy_cmd += [VMLINUX_OUT]
    subprocess.run(objcopy_cmd, check=True)

# Read section addresses from vmlinux
section_addrs = get_elf_sections(VMLINUX_IN)

add_symbols_args = []

with open(KALLSYMS_FILE, "r") as kf:
    for line in kf:
        # Line format: "<addr> <type> <name> [<module>]"
        parts = line.strip().split()
        if len(parts) < 3:
            continue
        addr_str, sym_type, sym_name = parts[0], parts[1], parts[2]

        # Skip module symbols
        if sym_name.endswith(']'):
            if '[' in line:
                continue

        # Determine section for this symbol
        addr_val = int(addr_str, 16)
        section = None
        for sec, (start, end) in section_addrs.items():
            if start <= addr_val < end:
                section = sec
                break
        # If not found, handle the symbol as absolute
        offset_val = addr_val
        if section:
            offset_val = addr_val - section_addrs[section][0]

        # Determine flags
        flags = []
        if sym_type.islower():
            flags.append("local")
        else:
            flags.append("global")
        if sym_type.lower() == 't':  # text code
            flags.insert(0, "function")
        else:
            # data (d,b,r) or others treated as object
            flags.insert(0, "object")

        # Construct the --add-symbol argument
        # --add-symbol name=[section:]value[,flags]
        if section:
            add_sym = f"{sym_name}={section}:{hex(offset_val)}"
        else:
            add_sym = f"{sym_name}={hex(offset_val)}"
        if flags:
            add_sym += "," + ",".join(flags)
        add_symbols_args.append("--add-symbol")
        add_symbols_args.append(add_sym)

# Create new vmlinux file
os.remove(VMLINUX_OUT)
shutil.copy2(VMLINUX_IN, VMLINUX_OUT)

# Add symbols
print(f"Adding {len(add_symbols_args)//2} symbols to '{VMLINUX_OUT}'")
for _ in tqdm(range((len(add_symbols_args)-1)//CHUNK_SIZE)):
    run_objcopy(add_symbols_args[:CHUNK_SIZE])
    add_symbols_args = add_symbols_args[CHUNK_SIZE:]
run_objcopy(add_symbols_args)

print("Done")

