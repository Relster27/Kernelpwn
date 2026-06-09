FROM ubuntu:24.04@sha256:4f1db91d9560cf107b5832c0761364ec64f46777aa4ec637cca3008f287c975e AS base
RUN apt update && apt install -y qemu-system-x86
WORKDIR /app
COPY --chmod=555 app/run .
COPY --chmod=444 app/rootfs.ext4 .
COPY --chmod=444 app/bzImage .
COPY --chmod=444 app/flag.txt .

FROM pwn.red/jail
COPY --from=base / /srv
ENV JAIL_TIME=300 JAIL_CPU=500 JAIL_MEM=256M JAIL_TMP_SIZE=33554432 JAIL_POW=15000 JAIL_CONNS_PER_IP=2
