FROM ubuntu:24.04@sha256:c4a8d5503dfb2a3eb8ab5f807da5bc69a85730fb49b5cfca2330194ebcc41c7b as chroot

RUN apt-get update && apt-get install -y socat qemu-system-x86 python3 && rm -rf /var/lib/apt/lists/*

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
