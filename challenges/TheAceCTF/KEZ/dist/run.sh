#!/bin/bash
cd $(dirname $0)
exec timeout --foreground 120 /usr/bin/qemu-system-x86_64 \
        -m 64M \
        -nographic \
        -monitor /dev/null \
        -kernel bzImage \
        -initrd rootfs.cpio.gz \
	-no-reboot \
	-append "console=ttyS0 quiet kaslr nosmep nosmap panic=1 oops=panic" \
	-net nic,model=virtio \
	-net user
