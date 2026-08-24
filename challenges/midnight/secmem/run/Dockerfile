FROM debian:12

RUN apt update -y && apt install -y socat libpixman-1-0 libfdt-dev libgio-2.0-dev libslirp0

COPY ./Image ./rootfs.ext4 ./start-qemu.sh /root/

WORKDIR /root/ 

COPY ./qemu-system-aarch64 /root/
CMD socat tcp-listen:4444,reuseaddr,fork exec:"/root/start-qemu.sh",pipes

