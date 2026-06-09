#!/usr/bin/python3
import base64
import subprocess
import sys
import tempfile
import os
import shutil
import secrets
import signal
import threading

QEMU_TIMEOUT_SECONDS = 90
QEMU_SHUTDOWN_GRACE_SECONDS = 5
QEMU_RUN_COUNT = 5
MAX_QEMU_LOG_BYTES = 2 * 1024 * 1024
MAX_SOLVE_BYTES = 2 * 1024 * 1024
MAX_SOLVE_B64_CHARS = 3 * 1024 * 1024
MAX_FLAG_BYTES = 4096
QEMU_DEBUG_EXIT_CODE = 0x42
QEMU_DEBUG_EXIT_RETURNCODE = (QEMU_DEBUG_EXIT_CODE << 1) | 1
FORBIDDEN_LOG_MARKERS = (
    b"Oops:",
    b"BUG:",
    b"Kernel panic",
    b"general protection fault",
    b"unable to handle",
)

INIT_SCRIPT = r"""#!/bin/sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null
mount -t tmpfs tmp /tmp 2>/dev/null

echo 2 >/proc/sys/kernel/kptr_restrict 2>/dev/null
echo 1 >/proc/sys/kernel/dmesg_restrict 2>/dev/null

mkdir -p /home/user /root
chmod 0755 /home /home/user
chmod 0700 /root
chmod 0600 /root/flag

echo "[coalmine] booting"

if ! /load_module /coalmine.ko; then
	echo "[coalmine] failed to load module"
	exec /poweroff_now
fi

chmod 0666 /dev/coalmine
echo "[coalmine] /dev/coalmine ready"

if [ "1" = "1" ]; then
	/launch_as_user /home/user/solve good
	rc=$?
	echo "COALMINE_AUTORUN_RC=$rc"
	echo "COALMINE_AUTORUN_DONE __AUTORUN_TOKEN__ $rc"
	exec /poweroff_now
fi

exec /launch_as_user /bin/sh
"""


_next_ino = 0x80000

def cpio_entry(name, data, mode=0o100755, uid=0, gid=0):
    global _next_ino
    _next_ino += 1
    ino = _next_ino
    namesize = len(name) + 1
    header = (
        f"070701"
        f"{ino:08X}"        # ino
        f"{mode:08X}"       # mode
        f"{uid:08X}"        # uid
        f"{gid:08X}"        # gid
        f"{1:08X}"          # nlink
        f"{0:08X}"          # mtime
        f"{len(data):08X}"  # filesize
        f"{0:08X}"          # devmajor
        f"{0:08X}"          # devminor
        f"{0:08X}"          # rdevmajor
        f"{0:08X}"          # rdevminor
        f"{namesize:08X}"   # namesize
        f"{0:08X}"          # check
    ).encode("ascii")
    name_bytes = name.encode("ascii") + b"\x00"
    header_plus_name = header + name_bytes
    pad1 = (4 - len(header_plus_name) % 4) % 4
    header_plus_name += b"\x00" * pad1
    result = header_plus_name + data
    pad2 = (4 - len(data) % 4) % 4
    result += b"\x00" * pad2
    return result


def cpio_trailer():
    return cpio_entry("TRAILER!!!", b"", mode=0)


def signal_process_group(proc, sig):
    try:
        os.killpg(proc.pid, sig)
    except ProcessLookupError:
        pass


class BoundedLog:
    def __init__(self, limit):
        self.limit = limit
        self._chunks = []
        self._size = 0
        self._scan_tail = b""
        self.truncated = False
        self.contains_forbidden_marker = False

    def append(self, chunk):
        if not chunk:
            return

        scan_data = self._scan_tail + chunk
        if any(marker in scan_data for marker in FORBIDDEN_LOG_MARKERS):
            self.contains_forbidden_marker = True
        max_marker_len = max(len(marker) for marker in FORBIDDEN_LOG_MARKERS)
        self._scan_tail = scan_data[-(max_marker_len - 1):]

        remaining = self.limit - self._size
        if remaining > 0:
            self._chunks.append(chunk[:remaining])
            self._size += min(len(chunk), remaining)
        if len(chunk) > remaining:
            self.truncated = True

    def bytes(self):
        return b"".join(self._chunks)


def run_qemu_capture(argv, timeout):
    log = BoundedLog(MAX_QEMU_LOG_BYTES)
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )

    def drain_output():
        assert proc.stdout is not None
        while True:
            chunk = proc.stdout.read(65536)
            if not chunk:
                break
            log.append(chunk)

    reader = threading.Thread(target=drain_output, daemon=True)
    reader.start()

    timed_out = False
    try:
        returncode = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        signal_process_group(proc, signal.SIGTERM)
        try:
            returncode = proc.wait(timeout=QEMU_SHUTDOWN_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            signal_process_group(proc, signal.SIGKILL)
            returncode = proc.wait()

    reader.join(timeout=QEMU_SHUTDOWN_GRACE_SECONDS)
    if proc.stdout is not None:
        proc.stdout.close()

    return (
        returncode,
        timed_out,
        log.bytes(),
        log.truncated,
        log.contains_forbidden_marker,
    )


def relay_qemu_log(log, truncated, contains_forbidden_marker):
    if contains_forbidden_marker:
        print("VM output suppressed", file=sys.stderr, flush=True)
        return

    if log:
        sys.stdout.buffer.write(log)
        if not log.endswith(b"\n"):
            sys.stdout.buffer.write(b"\n")
    if truncated:
        print(
            f"[coalmine] VM output truncated at {MAX_QEMU_LOG_BYTES} bytes",
            file=sys.stderr,
            flush=True,
        )
    sys.stdout.flush()


def qemu_argv(initrd_path):
    return [
        "/opt/qemu/bin/qemu-system-x86_64",
        "-m", "256M",
        "-smp", "1",
        "-cpu", "qemu64,+smep,+smap",
        "-kernel", "./bzImage",
        "-initrd", initrd_path,
        "-append", "console=ttyS0 kaslr quiet oops=panic panic=1",
        "-nographic",
        "-no-reboot",
        "-device", "isa-debug-exit,iobase=0xf4,iosize=0x01",
        "-monitor", "/dev/null",
    ]


def autorun_rc(log, autorun_token):
    marker = f"COALMINE_AUTORUN_DONE {autorun_token} ".encode()
    offset = log.rfind(marker)
    if offset < 0:
        return None
    tail = log[offset + len(marker):]
    value = tail.splitlines()[0].strip()
    if not value.isdigit():
        return None
    return int(value)


def validate_qemu_run(returncode, timed_out, log, contains_forbidden_marker, autorun_token):
    if contains_forbidden_marker:
        print("ERROR: VM output suppressed", file=sys.stderr, flush=True)
        sys.exit(1)
    if timed_out:
        print("ERROR: VM timed out", file=sys.stderr, flush=True)
        sys.exit(124)
    if returncode not in (0, QEMU_DEBUG_EXIT_RETURNCODE):
        sys.exit(returncode)
    rc = autorun_rc(log, autorun_token)
    if rc is None:
        print("ERROR: VM did not complete autorun", file=sys.stderr, flush=True)
        sys.exit(1)
    if rc != 0:
        sys.exit(rc)


def main():
    print("Send your solve binary as base64 (end with empty line):", flush=True)

    b64_lines = []
    b64_len = 0
    for line in sys.stdin:
        line = line.strip()
        if not line:
            break
        b64_len += len(line)
        if b64_len > MAX_SOLVE_B64_CHARS:
            print("ERROR: solve upload too large", file=sys.stderr)
            sys.exit(1)
        b64_lines.append(line)

    if not b64_lines:
        print("ERROR: no input received", file=sys.stderr)
        sys.exit(1)

    b64_str = "".join(b64_lines)
    b64_str = b64_str.replace("\r", "").replace("\n", "").replace(" ", "")
    padding = (4 - len(b64_str) % 4) % 4
    b64_str += "=" * padding

    try:
        solve_bin = base64.b64decode(b64_str)
    except Exception as e:
        print(f"ERROR: invalid base64: {e}", file=sys.stderr)
        sys.exit(1)

    if len(solve_bin) > MAX_SOLVE_BYTES:
        print("ERROR: solve binary too large", file=sys.stderr)
        sys.exit(1)

    print(f"Received {len(solve_bin)} byte solve binary", flush=True)

    try:
        with open("/flag", "rb") as flag_file:
            flag_data = flag_file.read(MAX_FLAG_BYTES + 1)
    except OSError as e:
        print(f"ERROR: failed to read /flag: {e}", file=sys.stderr)
        sys.exit(1)

    if len(flag_data) > MAX_FLAG_BYTES:
        print("ERROR: flag file too large", file=sys.stderr)
        sys.exit(1)

    workdir = tempfile.mkdtemp()
    try:
        autorun_token = secrets.token_hex(16)
        init_script = INIT_SCRIPT.replace("__AUTORUN_TOKEN__", autorun_token)
        overlay = (
            cpio_entry("home/user/solve", solve_bin, mode=0o100755, uid=1000, gid=1000)
            + cpio_entry("root/flag", flag_data, mode=0o100600)
            + cpio_entry("init", init_script.encode(), mode=0o100700)
            + cpio_trailer()
        )

        combined_path = os.path.join(workdir, "initramfs.cpio")
        with open("initramfs.cpio", "rb") as orig:
            orig_data = orig.read()
        with open(combined_path, "wb") as f:
            f.write(orig_data)
            f.write(overlay)

        print("Launching VM...", flush=True)
        last_qemu_log = b""
        last_log_truncated = False
        last_qemu_log_contains_forbidden_marker = False

        for _ in range(QEMU_RUN_COUNT):
            (
                returncode,
                timed_out,
                qemu_log,
                log_truncated,
                qemu_log_contains_forbidden_marker,
            ) = run_qemu_capture(
                qemu_argv(combined_path),
                timeout=QEMU_TIMEOUT_SECONDS,
            )
            validate_qemu_run(
                returncode,
                timed_out,
                qemu_log,
                qemu_log_contains_forbidden_marker,
                autorun_token,
            )
            last_qemu_log = qemu_log
            last_log_truncated = log_truncated
            last_qemu_log_contains_forbidden_marker = qemu_log_contains_forbidden_marker

        relay_qemu_log(
            last_qemu_log,
            last_log_truncated,
            last_qemu_log_contains_forbidden_marker,
        )
    finally:
        shutil.rmtree(workdir)


if __name__ == "__main__":
    main()
