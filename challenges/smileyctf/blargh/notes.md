Vuln:
- OOB di blargh_ioctl()
- Write 1 byte ('\x00') doang
- ioctl() cuma bisa sekali?? (karena variable 'writes' diset ke 0 setelah
    ioctl() pertama dilakukan)

Step-to-solve:
- Patch 

