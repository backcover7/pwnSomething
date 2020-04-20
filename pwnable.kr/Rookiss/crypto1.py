from pwn import *
import hashlib

'''
Let pw=''
a*12 + '-' + '-' + {cookie} -> len(encrypted_data) = 128 / 2 = 64      # because of hex
a*13 + '-' + '-' + {cookie} -> len(encrypted_data) = 160 / 2 = 80

Because the block size is 16

13 + 2 + len(cookie) + 16 * '0' = 80                                # When the previous block is exactly filled, it needs another empty block to append
len(cookie) = 49

[________________][________________][________________][_____________--*][0000000000000000]      // len(ciphertext) = 160
[     {id}-{pw}-y][ou_will_never_g][uess_this_sugar_h][oney_salt_cookie]                        // id part is padded by '_', assume pw is ''
...
[________________][________________][________________][_____________--y][0000000000000000]      // First Match!   getCipherText(pkt)[:block_offset * 16 * 2] is the part of the first four blocks.

When we do not insert the cookie, we just pad the id part, and also we control the pw part is null.
So the {cookie} is actually appended after the [________________][________________][________________][_____________   ].

'''

cookie = ''
separations = '--'
COOKIE_LEN = 49
block_offset = COOKIE_LEN / 16 + 1                                      # meet the requirement of the least length of cookie

log.progress("Waiting for exhausted searching...")

def getCipherText(pkt):
    p = remote("pwnable.kr", 9006)
    p.recvuntil("ID\n")
    p.sendline(pkt)
    p.recvuntil("PW\n")
    p.sendline()
    p.recvuntil("(")
    ciphertext = p.recvuntil(")").strip(")")
    p.close()
    return ciphertext

for i in xrange(0, COOKIE_LEN):                                     # brute-force the cookie by bytes
    pad_len = block_offset * 16 - len(separations) - i - 1          # padding with '_' in the first 4 blocks without separationsarations
    pkt = '_' * pad_len
    context.log_level = 'error'
    hash1 = getCipherText(pkt)[:block_offset * 16 * 2]
    
    for char_cookie in '-_abcdefghijklmnopqrstuvwxyz0123456789':
        pkt = '_' * pad_len + separations + cookie[:i] + char_cookie
        hash2 = getCipherText(pkt)[:block_offset * 16 * 2]
        if hash1 == hash2:
            cookie += char_cookie
            context.log_level = 'info'
            log.warn('Current Cookie: {0}'.format(cookie))
            break

id = 'admin'
pw = hashlib.sha256(id + cookie).hexdigest()

log.info("ID: {0}".format(id))
log.info("PW: {0}".format(pw))
log.info('Cookie: {0}'.format(cookie))

p = remote("pwnable.kr", 9006)
p.recvuntil("ID\n")
p.sendline(id)
p.recvuntil("PW\n")
p.sendline(pw)
p.recvuntil("flag\n")
log.success("Flag: " + p.recvline())