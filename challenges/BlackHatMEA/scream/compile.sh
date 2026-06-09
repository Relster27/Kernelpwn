#!/bin/bash

musl-gcc exploit.c -I/usr/local/include -L/usr/local/lib -lrlstr -o exploit -static #-no-pie
chmod +x exploit
cp exploit /home/relster/ctf/bhmea25/final/scream/app/mntfs/
ls /home/relster/ctf/bhmea25/final/scream/app/mntfs