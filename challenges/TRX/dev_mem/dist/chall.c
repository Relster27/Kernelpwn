#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <err.h>

#define DEV "/dev/mem"

#define PAGE_SIZE 0x1000
#define GET_PAGE_BASE(address) address & ~(PAGE_SIZE-1)
#define GET_OFFSET(address) address & (PAGE_SIZE-1) 

__attribute__((constructor)) void init();
int get_long(char* str, unsigned long* value);
int physical_write(int dev, unsigned long address, unsigned long value);

__attribute__((constructor))
void init(){
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    setbuf(stdin, NULL);
}

int get_long(char* str, unsigned long* value){
    char* check;

    *value = strtoul(str, &check, 16);

    if(check == str)
        return 1;
    
    return 0;
}

int physical_write(int dev, unsigned long address, unsigned long value){
    int br;

    if(lseek(dev, address, SEEK_SET) == -1)
        return 1;

    br = write(dev, &value, sizeof(unsigned long));

    if(br == -1)
        return 1;
    
    return 0;
}

int main(int argc, char **argv){
    unsigned long address, value;
    int dev, check;

    dev = open(DEV, O_RDWR | O_SYNC);
    if(dev == -1)
        err(1, "could not open " DEV);

    if(argc != 3) {
        puts("./chall <address> <value>");
        return 1;
    }
    
    check = get_long(argv[1], &address);
    if(check || (address & (sizeof(unsigned long)-1)) != 0){
        puts("invalid address");
        return 1;
    }

    check = get_long(argv[2], &value);
    if(check){
        puts("invalid value");
        return 1;
    }

    if(physical_write(dev, address, value) != 0)
        err(1, "could not interact with " DEV);

    close(dev);
    return 0;
}