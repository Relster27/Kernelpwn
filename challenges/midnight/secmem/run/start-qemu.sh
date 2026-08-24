#!/bin/sh

exec ./qemu-system-aarch64 -M virt -cpu cortex-a710 -nographic -smp 1 -kernel Image -append "quiet rootwait root=/dev/vda console=ttyAMA0 kaslr" -netdev user,id=eth0,hostfwd=tcp::2222-:22,hostfwd=tcp::1337-:1337 -device virtio-net-device,netdev=eth0 -drive file=rootfs.ext4,if=none,format=raw,id=hd0 -device virtio-blk-device,drive=hd0  ${EXTRA_ARGS} "$@"
