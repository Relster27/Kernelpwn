Run from this directory:

  ./run.sh

Equivalent QEMU command:

  qemu-system-x86_64 -m 256M -smp 1 -cpu qemu64,+smep,+smap -kernel ./bzImage -initrd ./initramfs.cpio -append "console=ttyS0 kaslr quiet oops=panic panic=1" -nographic -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=0x01 -monitor /dev/null
