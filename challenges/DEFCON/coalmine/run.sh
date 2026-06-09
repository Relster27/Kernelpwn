#!/bin/sh
set -eu

exec timeout 90s qemu-system-x86_64 \
	-m 256M \
	-smp 1 \
	-cpu qemu64,+smep,+smap \
	-kernel ./bzImage \
	-initrd ./initramfs.cpio \
	-append "console=ttyS0 kaslr quiet oops=panic panic=1" \
	-nographic \
	-no-reboot \
	-monitor /dev/null
