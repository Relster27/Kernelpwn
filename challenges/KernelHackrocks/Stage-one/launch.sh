#!/bin/bash

#
# launch
#
timeout --foreground 28800 /usr/bin/qemu-system-x86_64 \
	-kernel ./bzImage \
	-initrd ./initramfs.cpio.gz \
	-nographic \
	-monitor none \
	-no-reboot \
	-append "console=ttyS0 nokaslr nosmap nosmep nokpti quiet panic=1 oops=panic"
