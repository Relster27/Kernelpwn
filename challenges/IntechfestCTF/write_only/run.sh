#!/bin/bash
cd $(dirname $0)
#exec timeout --foreground 120 /usr/bin/qemu-system-x86_64 \
exec timeout --foreground 9999 /usr/bin/qemu-system-x86_64 \
        -m 64M \
        -cpu kvm64,+smep,+smap \
        -nographic \
        -monitor /dev/null \
        -kernel bzImage \
        -initrd rootfs.cpio.gz \
	      -no-reboot \
	      -append "console=ttyS0 quiet nokaslr panic=1 kpti=1 oops=panic" \
	      -net nic,model=virtio \
	      -net user \
        -s
