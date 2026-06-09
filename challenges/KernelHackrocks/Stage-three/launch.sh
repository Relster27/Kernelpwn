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
	-cpu kvm64,+smap,+smep\
	-append "console=ttyS0 kaslr kpti quiet panic=1 oops=panic" \
	-s
