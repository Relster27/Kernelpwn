#!/bin/bash

# Compress initramfs with the included statically linked exploit

musl-gcc exploit.c -I/usr/local/include -L/usr/local/lib -lrlstr -o exploit -static -no-pie
mv exploit initramfs
# musl-gcc exploit2.c -I/usr/local/include -L/usr/local/lib -lrlstr -o exploit2 -static -no-pie
# mv exploit2 initramfs

pushd . && pushd initramfs
find . -print0 | cpio --null --format=newc -o 2>/dev/null | gzip -9 > ../initramfs.cpio.gz
popd
