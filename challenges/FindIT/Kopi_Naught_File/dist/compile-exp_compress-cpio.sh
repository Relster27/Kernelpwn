#!/bin/bash

# Compress initramfs with the included statically linked exploit
in=$1
out=$(echo $in | awk '{ print substr( $0, 1, length($0)-2 ) }')
musl-gcc $in -g -O0 -I/usr/local/include -L/usr/local/lib -lrlstr -static -no-pie -o $out || exit 255
mv $out initramfs/tmp/

# Compress initramfs and FORCE root ownership
pushd . && pushd initramfs

# The --owner root:root flag is the magic fix here
find . -print0 | cpio --null --format=newc -o --owner root:root 2>/dev/null | gzip -9 > ../initramfs.cpio.gz

popd
