#!/bin/bash

musl-gcc -static -no-pie exploit.c -o exploit
sudo cp exploit rootfs/
sudo ./compile_exp_and_compress.sh

