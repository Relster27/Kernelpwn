#!/usr/bin/env python3
from pwn import *
import subprocess
import sys


def solve_pow(p):
    data = p.recvuntil(b"solution:")

    log.info("PoW prompt:")
    log.info(data.decode(errors="replace"))

    pow_cmd = None

    for line in data.decode(errors="replace").splitlines():
        line = line.strip()
        if line.startswith("curl ") and "pwn.red/pow" in line:
            pow_cmd = line
            break

    if pow_cmd is None:
        log.error("Could not find PoW command")

    log.info("Executing PoW locally:")
    log.info(pow_cmd)

    result = subprocess.run(
        pow_cmd,
        shell=True,
        capture_output=True,
        text=True,
        check=True,
    )

    solution = result.stdout.strip()

    log.info("PoW solution:")
    log.info(solution)

    p.sendline(solution.encode())

    # Give the remote side time to transition to the shell.
    sleep(0.5)

    # Show whatever the server sends after the PoW.
    try:
        data = p.recv(timeout=2)

        if data:
            log.info("Post-PoW data:")
            log.info(repr(data))

            # Put it back so send_command() can consume it.
            p.unrecv(data)

    except EOFError:
        log.failure("Remote closed connection after PoW")
        raise


def send_command(cmd, print_cmd=True, print_resp=False):
    if print_cmd:
        log.info("$ " + cmd)

    p.sendlineafter(b"$", cmd.encode())

    resp = p.recvuntil(b"$")

    if print_resp:
        log.info(repr(resp))

    # Preserve the prompt for the next command.
    p.unrecv(b"$")

    return resp


def send_file(src, dst):
    with open(src, "rb") as f:
        file = f.read()

    encoded = b64e(file)

    if isinstance(encoded, bytes):
        encoded = encoded.decode()

    # Remove trailing slash so /tmp/ becomes /tmp/exp.b64
    dst = dst.rstrip("/")

    send_command(f"rm -f {dst}.b64")
    send_command(f"rm -f {dst}")

    size = 800
    total = (len(encoded) + size - 1) // size

    for i in range(0, len(encoded), size):
        chunk = encoded[i:i + size]

        log.info(
            "Sending chunk %d/%d",
            i // size + 1,
            total
        )

        send_command(
            f"echo -n '{chunk}' >> {dst}.b64",
            print_cmd=False
        )

    send_command(
        f"cat {dst}.b64 | base64 -d > {dst}"
    )

    send_command(
        f"chmod +x {dst}"
    )

    log.success(f"Uploaded {src} -> {dst}")


def main():
    if len(sys.argv) != 5:
        print(
            f"usage: {sys.argv[0]} "
            "<IP> <PORT> <FILE TO SEND> <PATH ON REMOTE>"
        )
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    src = sys.argv[3]
    dst = sys.argv[4]

    context.log_level = "info"

    global p
    p = remote(host, port)

    # Solve the PoW supplied by this connection.
    solve_pow(p)

    # Upload the exploit.
    send_file(src, dst)

    # Drop to interactive shell.
    p.interactive()


if __name__ == "__main__":
    main()

