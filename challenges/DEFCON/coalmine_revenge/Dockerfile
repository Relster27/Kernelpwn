FROM ubuntu:24.04@sha256:c4a8d5503dfb2a3eb8ab5f807da5bc69a85730fb49b5cfca2330194ebcc41c7b as chroot

RUN apt-get update && apt-get install -y socat python3 git libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev ninja-build python3-pip python3-setuptools python3-tomli python3-wheel wget && rm -rf /var/lib/apt/lists/*

# qemu@f5a2438405d4ae8b62de7c9b39fac0b2155ee544
RUN mkdir -p /opt/qemu
WORKDIR /opt/qemu
RUN wget https://storage.googleapis.com/gha-quals-2026-handout-production/qemu.tar.gz && tar xf qemu.tar.gz && mv bin bin2 && mkdir bin && mv bin2/qemu-system-x86_64 bin && rm -rf bin2

RUN useradd -m birb

COPY bzImage /home/birb/bzImage
COPY initramfs.cpio /home/birb/initramfs.cpio
COPY run.sh /home/birb/run.sh
COPY entrypoint.py /home/birb/entrypoint.py

RUN chmod +x /home/birb/run.sh /home/birb/entrypoint.py

FROM ghcr.io/bbb-ctf/quals-template-jail:20e797bf2baa09ac1ab0f6894c03dbcdacac9012
COPY --from=chroot / /chroot
COPY nsjail.cfg /home/user/
COPY flag /flag
RUN chown user:user /chroot/home/birb
RUN touch /chroot/flag

EXPOSE 1337

CMD ["kctf_setup", "socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:kctf_nsjail_flag_at /flag -- /home/birb/entrypoint.py"]
