#!/bin/bash

# Compress initramfs with the included statically linked exploit
in=$1
out=$(echo $in | awk '{ print substr( $0, 1, length($0)-2 ) }')
#gcc $in -static -o $out || exit 255 # remote
gcc $in -g -O0 -o $out || exit 255
mv $out rootfs

pushd . && pushd rootfs
find . -print0 | cpio --null --format=newc -o 2>/dev/null | gzip -9 > ../rootfs.cpio.gz
popd
