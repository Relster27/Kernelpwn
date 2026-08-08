#!/bin/sh

exec qemu-system-x86_64 \
    -m 64M \
    -kernel bzImage \
    -initrd initramfs.cpio.gz \
    -append "console=ttyS0 quiet kaslr" \
    -drive file=flag.txt,format=raw,index=0,media=disk,snapshot=on \
    -no-reboot \
    -cpu kvm64,+smep,+smap \
    -net nic,model=virtio \
    -net user \
    -nographic \
    -monitor /dev/null \
    -serial mon:stdio \
    -gdb tcp::1234
