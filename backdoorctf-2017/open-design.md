# open-design
**Description**: TODO

## The challenge

The challenge provided access to a server via ssh login as an unprivileged user.
Logging in to the server, we see a single binary in the user's home directory:

```bash
$ ls
---x--x--x 1 root root  0 24. Sep 21:47 open-design
```

I didn't even know you could have executable but non-readable files on Linux.
But, to my surprise, executing it works just fine!

```bash
$ ./open-design
$
```

Nothing interesting happens though. 
We need to find out more about what that binary does.
Unfortunately, just as the permissions say, we really cannot read it:

```bash
$ cat ./open-design
cat: ./open-design: Permission denied
```

Before we can progress any further, we need to find a way to get access to the binary.

## Gathering knowledge: dumping the binary

While we cannot read the binary from the file system, Linux must load it into memory for execution.
Therefore, if we manage to inject code into our target process, we can dump the memory content and retrieve the binary this way.

Luckily for us, the program is dynamically linked (a quick `env LD_DEBUG=all ./open-design` confirms that it loads dynamic libraries).
This means that function references are resolved at run-time.
We can make the linker look for symbols in our own library *first* by using [`LD_PRELOAD=./our-own-library.so`](http://nairobi-embedded.org/elf_ld_preload.html). 
Any symbol we define in our own library will take precedence over symbols defined in other libraries, so we can effectively replace any dynamically linked function with our own implementation.

What would be a good target to replace? 
During the CTF, I used some other targets first but in the end I settled on `__libc_start_main`.
The function is called early during program startup to setup everything and then launch into the real `main`.
Overriding this function gives us a lot of control, while at the same time not destroying normal function of the program, because we can just call the original `__libc_start_main` at the end of our hook.

To dump the binary, we can override the `main` function pointer that is passed to `__libc_start_main` to run our own function as if it was the main function of the binary:

```c
// our own implementation of __libc_start_main (I copied the function signature from Google search results :)
int __libc_start_main (int (*main)(int, char**, char**), int argc, char * * ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end)) {
  // lookup the original __libc_start_main (yes, c function pointer syntax is weird)
  int (*real_start_main)(int (*main) (int, char**, char**), int argc, char** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end)) = dlsym(RTLD_NEXT, "__libc_start_main");

  // call original __libc_start_main, but replace "main" with our custom implementation
  return real_start_main(&custom_main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}
```
(Note: to compile this code, you need to `#define _GNU_SOURCE` before `#include <dlfcn.h>` or the `RTLD_NEXT` constant is not defined)

In our custom main, we dump the binary. 
To figure out which part of the memory to dump, we read the file `/proc/self/maps`, which tells us which
part of the binary is loaded at which point in memory:

```c
int custom_main(int argc, char** argv, char** envp) {
  // parse /proc/self/maps and dump it
  FILE* maps = fopen("/proc/self/maps", "r"); 
  size_t n = 0;
  char* line = NULL;
  while(getline(&line, &n, maps) >= 0) {
    // skip mappings which don't belong to open design
    if(!strstr(line, "open-design")) continue;

    // parse start/end address from line
    char* start = (char*)strtoll(strtok(line, "-"), NULL, 16);
    char* end = (char*)strtoll(strtok(NULL, " "), NULL, 16);

    // dump to file
    char outname[100];
    snprintf(outname, 100, "dump.%llx", (long long)start);
    FILE* out = fopen(outname, "wb");
    fwrite(start, 1, (long long)(end - start), out);
    fclose(out);
  }

  free(line);
  fclose(maps);

  printf("dumped process!\n");
  return 0;
}
```

Then we compile this code into a shared library and inject it with `LD_PRELOAD`:

```bash
$ gcc -shared -fPIC -Wall dumper.c -o dumper.so
$ env LD_PRELOAD=./dumper.so ~/open-design
dumped process!
```

If everything goes well, we should end up with three files `dump.400000, dump.600000, dump.601000` in the current directory.

## Reversing: analyzing the binary

If we take a look at the files we've got, we find that the binary was mapped at address `0x600000` since that contains the elf headers:

```bash
$ file dump.600000
dump.600000: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, missing section headers
```

It is missing the section headers, because those are located at the end of the binary.
But the binary is small enough that `dump.601000` which is a segment directly after `dump.600000` contains the section headers.
We can just `cat` both dumps together to obtain an almost complete binary:

```bash
$ cat dump.600000 dump.601000 > binary
$ chmod +x binary
```

Now we can load the binary in IDA and take a look at the main function:

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  return 0LL;
}
```

So the binary really didn't do anything at all. 
But, looking at the imported symbols of the binary we notice that it has references to `puts` and `rand`, which is suspicious for a binary without any code.
Following those references, we find a hidden function at address `0x400666`:

```c
__int64 __fastcall sub_400666(const char *a1)
{
  char v1; // bl@9
  signed int seed; // [sp+10h] [bp-50h]@1
  int i; // [sp+14h] [bp-4Ch]@1
  int j; // [sp+14h] [bp-4Ch]@4
  signed int k; // [sp+14h] [bp-4Ch]@8
  char v7[34]; // [sp+20h] [bp-40h]@5
  char v8; // [sp+42h] [bp-1Eh]@11
  __int64 v9; // [sp+48h] [bp-18h]@1

  v9 = v28;
  seed = 1;
  for ( i = 0; i < strlen(&s); ++i )
    seed += *(&s + i + 1) * *(&s + i) + *(&s + i + 2);
  for ( j = 0; j < strlen(a1); ++j )
  {
    if ( a1[j] != (v7[j] != *((_BYTE *)qword_400858 + j)) )
      return v28 ^ v9;
  }
  srand(seed);
  for ( k = 0; k <= 33; ++k )
  {
    v1 = *((_BYTE *)qword_400858 + k);
    v7[k] = rand() ^ v1;
  }
  v8 = 0;
  puts(v7);
  return v28 ^ v9;
}
```

The code first computes a seed, then compares the argument to some other string and finally prints out a string generated with `rand()`.
It is likely that the string printed out at the end is the flag.
Because the generated string does not depend on the argument value at all, we can pass `""` for the argument to avoid the check.

To call the function, we can re-use the code from our dumper for replacing `main`, this time calling the function instead of dumping the binary:

```c
int custom_main(int argc, char** argv, char** envp) {
  void (*target_function)(char* arg) = 0x400666;
  (*target_function)("");
}
```

Running that the same way as before using `LD_PRELOAD` we obtain the flag.
