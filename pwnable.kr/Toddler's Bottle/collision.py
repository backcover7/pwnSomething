from pwn import *

conn = ssh(host="pwnable.kr", port=2222, user="col", password="guest")

payload = '\x01'*16 + '\xe8\x05\xd9\x1d'
p = conn.process(["./col", payload])
log.success(p.recv(512))
