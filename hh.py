```py
from z3 import *

def ROLL(x, n):
    return RotateLeft(x, n)

def RORL(x, n):
    return RotateRight(x, n)

def encrypt_z3(arg1):
    # Following the assembly instructions exactly
    x = arg1
    x = ROLL(x, 0x7)
    x = ROLL(x, 0x9)
    x = x + 0x2c136b50
    x = RORL(x, 0xa)
    x = RORL(x, 0x9)
    x = x + 0x5e33d9f1
    x = RORL(x, 0x3)
    x = x ^ 0x72784dfc
    x = ROLL(x, 0x5)
    x = x ^ 0x387d6a04
    x = x - 0x6bc52a8e
    x = x + 0x51c5dcc9
    x = RORL(x, 0x9)
    x = x - 0x28bc5579
    x = x - 0x58101e53
    x = x - 0x4fa73bee
    x = x + 0xfac1f4c
    x = ROLL(x, 0x7)
    x = ROLL(x, 0x7)
    x = x + 0x7b270093
    x = x - 0x44f7ed91
    x = x - 0x64ca7e9b
    x = x + 0x35368062
    x = x + 0x5421f3b4
    x = x ^ 0x1a952c88
    x = x - 0x52f1cddb
    x = x - 0x3d0fb170
    x = RORL(x, 0x2)
    x = ROLL(x, 0xa)
    return x & 0xFFFFFFFF  # 32-bit result

def to_int_z3(chars, offset):
    result = BitVecVal(0, 32)
    str_len = len(chars)  # Length of input buffer
    
    for i in range(4):
        curr_pos = offset + i
        # For each position, create the character selection logic
        char_val = chars[offset + i] if offset + i < str_len else chars[str_len - 1]
        result = (result << 8) ^ ZeroExt(24, char_val)
    
    return result

# Target values from the decompiled code
targets = [
    0x62f4abc9,  # local_48[0]
    0xdf0dc98e,  # local_48[1]
    0x909d09c8,  # local_48[2]
    0xc24e3898,  # local_48[3]
    0xc2ce9ab8,  # local_38
    0x224dc9c9,  # local_34
    0xe03e99c8,  # local_30
    0x40f36748,  # local_2c
    0xd0ee7719,  # local_28
    0xbf9cc868   # local_24
]

# Create solver
s = Solver()

# Create symbolic variables for input (41 bytes)
input_chars = [BitVec(f'c_{i}', 8) for i in range(41)]

# Add constraints for printable ASCII
for c in input_chars:
    s.add(And(c >= 32, c <= 126))

# Process input in 4-byte chunks
for i in range(0, 0x28, 4):
    chunk_val = to_int_z3(input_chars, i)
    encrypted = encrypt_z3(chunk_val)
    s.add(encrypted == targets[i // 4])

# Set timeout and memory limit
s.set("timeout", 300000)  # 5 minute timeout
print("Solving...")

if s.check() == sat:
    m = s.model()
    result = ''
    for i in range(41):
        c = m[input_chars[i]].as_long()
        result += chr(c)
    print(f"Solution found: {result}")
    
    # Verify solution
    print("\nVerifying solution by chunks:")
    for i in range(0, 0x28, 4):
        chunk = result[i:i+4]
        print(f"Chunk {i//4}: {chunk}")
else:
    print("No solution found")
    print("Reason:", s.reason_unknown())
```