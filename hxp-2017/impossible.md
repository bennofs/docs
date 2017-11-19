# Impossible (pwn 400 + 100 bonuspoints)
**Description:** please hack   
**Exploit script:** [impossible.py](./impossible.py)

## Challenge
The challenge binary behaves like this C code:

```c
int main() {
  int result;

  size_t size;
  char* base_block;

  // allocate a block of user-specified size with calloc
  if ( scanf("%zx", &size) == 1 && (base_block = calloc(size, 1uLL)) != 0LL ) {
      while ( 1 ) {
        // overwrite base_block + user-specified offset with user-specified byte
        char byte = 0;
        size_t idx;
        if ( scanf("%zx %hhx", &idx, &byte) != 2 )
          break;
        *(base_block + idx) = byte;
      }
      result = 0;
  } else {
    puts(":(");
    result = -1;
  }
  return result;
}
```

So after giving a size, we can then write as many times as we want at any offset relative to a heap block of that size.

We have the following protections:

```
$ checksec vuln
[*] '/code/hxp17/impossible/vuln'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

The binary is a position-independent executable which means that there is no address in memory that is not randomized.

## Approach
We already have an arbitrary write, if we know the offset of the target from our heap block.
Since the heap base is randomized on start, the only things that have known offsets from our heap block are other heap blocks.
Except in one case: if we choose size larger than `mmap_threshold` (by default, this is `128 * 1024 = 0x20000`), then `malloc` will use `mmap` directly to allocate space for our block, instead of placing it on the normal heap space.
Now, on Linux, there is only a single random offset `mmap_base` that is shared by *all* calls to `mmap`. So if you mmap two blocks one after another, while the absolute address is randomized due to ASLR, both will always end up directly next to each other.

The nice thing about the above fact is that `ld.so` will also use `mmap` to map shared library's segments into memory.
By requesting a large size, our block will be placed at a constant offset from the libc base, as we can verify with GDB:

```
(gdb) set disable-randomization off
(gdb) r
Starting program: /code/hxp17/impossible/vuln
400000
^Z
Program received signal SIGTSTP, Stopped (user).
0x00007ffff7b07971 in __GI___libc_read (fd=0, buf=0x555555756260, nbytes=1024) at ../sysdeps/unix/sysv/linux/read.c:26
26        return SYSCALL_CANCEL (read, fd, buf, nbytes);
(gdb) info proc mappings
process 29984
Mapped address spaces:


          Start Addr           End Addr       Size     Offset objfile
      0x55f5085ce000     0x55f5085cf000     0x1000        0x0 /code/hxp17/impossible/vuln
      0x55f5087ce000     0x55f5087cf000     0x1000        0x0 /code/hxp17/impossible/vuln
      0x55f5087cf000     0x55f5087d0000     0x1000     0x1000 /code/hxp17/impossible/vuln
      0x55f50a605000     0x55f50a626000    0x21000        0x0 [heap]
      0x7f0b0c9f6000     0x7f0b0cdf7000   0x401000        0x0
      0x7f0b0cdf7000     0x7f0b0cfa5000   0x1ae000        0x0 /usr/lib/libc-2.26.so
      0x7f0b0cfa5000     0x7f0b0d1a5000   0x200000   0x1ae000 /usr/lib/libc-2.26.so
      0x7f0b0d1a5000     0x7f0b0d1a9000     0x4000   0x1ae000 /usr/lib/libc-2.26.so
      0x7f0b0d1a9000     0x7f0b0d1ab000     0x2000   0x1b2000 /usr/lib/libc-2.26.so
      0x7f0b0d1ab000     0x7f0b0d1af000     0x4000        0x0
      0x7f0b0d1af000     0x7f0b0d1d4000    0x25000        0x0 /usr/lib/ld-2.26.so
      0x7f0b0d38c000     0x7f0b0d38e000     0x2000        0x0
      0x7f0b0d3d3000     0x7f0b0d3d4000     0x1000    0x24000 /usr/lib/ld-2.26.so
      0x7f0b0d3d4000     0x7f0b0d3d5000     0x1000    0x25000 /usr/lib/ld-2.26.so
      0x7f0b0d3d5000     0x7f0b0d3d6000     0x1000        0x0
      0x7ffd941ae000     0x7ffd941cf000    0x21000        0x0 [stack]
      0x7ffd941e6000     0x7ffd941e9000     0x3000        0x0 [vvar]
      0x7ffd941e9000     0x7ffd941eb000     0x2000        0x0 [vdso]
  0xffffffffff600000 0xffffffffff601000     0x1000        0x0 [vsyscall]
```

Notice how our allocated block at `0x7f0b0c9f6000` is always allocated directly below the segments of glibc.
This means that everything in the data segment of glibc is at a fixed offset from our block, allowing us to override it with arbitrary data.

A very good target to override is the `struct _IO_FILE` for stdout and stdin.
In particular, glibc will flush stdout before reading from line or unbuffered stdin [if the `_IO_LINE_BUF` flag is set on stdout](https://github.com/lattera/glibc/blob/a2f34833b1042d5d8eeb263b4cf4caaea138c4ad/libio/fileops.c#L587).
We can overwrite stdout's buffer pointers and set the flags correctly to leak data at arbitrary (absolute) addresses.
To leak the libc base (necessary because the buffer pointers are absolute and not relative anymore), we make use of the fact that for unbuffered stdout, the buffer points to the field `_shortbuf` (part of `_IO_FILE`).
If we overwrite the buffer pointer to set the LSB to zero, we will move it backwards so on the next flush parts of the `_IO_FILE` structure will be printed.
Some fields of `_IO_FILE` are pointers into libc so we can compute the libc base from that.

Before the overwrite, stdout will look like this:

```
stdout = {
  /* ... */
  _IO_read_end = 0x7fa40ce9f623 <_shortbuf> "",
  _IO_write_base = 0x7fa40ce9f623 <_shortbuf> "",
  /* ... */
  _markers = 0x0,
  _chain = 0x7f9ddae9b860 <_IO_2_1_stdin_>,
  /* ... */
  char _shortbuf[1] = "";
}
```

Then we overwrite `_IO_read_end` and `_IO_write_base` to get:


```
stdout = {
  /* ... */
  _IO_read_end = 0x7fa40ce9f600 <_markers> "",
  _IO_write_base = 0x7fa40ce9f600 <_markers> "",
  
  /* ... */
  _markers = 0x0,
  _chain = 0x7f9ddae9b860 <_IO_2_1_stdin_>,

  /* ... */
  char _shortbuf[1] = "";
}
```

So `_IO_write_base` now points at the `_markers` field and the next flush will print the contents of `_chain` to stdout from which we can compute the libc base.

At this point, we now have a arbitrary read (by overwrite stdio's buffer) in addition to an arbitrary write.
Because the binary has full RELRO, we cannot write to the GOT to get arbitrary code execution since it is read-only.
Instead, I chose to leak a stack pointer (the `program_invocation_name` global variable conveniently available in glibc's data segment) and overwrite `main`'s stack frame to return into `execv("/bin/sh", 0)`.
Another option could have been to overwrite the `atexit` handlers or other function pointer structures in glibc.

Take a look at the [exploit script](./impossible.py) for all the technical details.

**Flag:** hxp{l04d3r_0r13nt3d_pr0gr4mm1ng_15_4_th1ng}

## References

If you want to understand file handling in glibc in more depth, here's some pointers to get you started:

* [`_IO_new_file_underflow`](https://github.com/bminor/glibc/blob/2767ebd8bc34c8b632ea737296200a86f57289ad/libio/fileops.c#L522): the function responsible for reading from a file like stdin in glibc
* [`_IO_new_file_overflow`](https://github.com/bminor/glibc/blob/2767ebd8bc34c8b632ea737296200a86f57289ad/libio/fileops.c#L798): the function responsible for writing to a file like stdout in glibc
* [`_IO_doallocbuf`](https://github.com/bminor/glibc/blob/2767ebd8bc34c8b632ea737296200a86f57289ad/libio/genops.c#L393) 
* [`struct _IO_FILE` definition](https://github.com/bminor/glibc/blob/2767ebd8bc34c8b632ea737296200a86f57289ad/libio/libio.h#L241)
* [definition of the flag constants](https://github.com/bminor/glibc/blob/2767ebd8bc34c8b632ea737296200a86f57289ad/libio/libio.h#L92): flags like `_IO_UNBUFFERED` etc.

A link I found after the CTF (explains exactly this situation): https://github.com/kirschju/wiedergaenger
