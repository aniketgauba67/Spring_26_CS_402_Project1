import random

# Step 1: List all group members' D-numbers (keep the 'D' as required)
d_numbers = [
    "D02001156",    #Hyeonseo Lee
    "D01959347",    #Thomas Ripley
    "D01968637",    #Aniket Gauba
]

# Step 2: Extract the numeric part of each D-number to determine the seed
numeric_values = []

for d in d_numbers:
    # Remove the leading 'D' and convert to an integer
    number_only = int(d[1:])
    numeric_values.append(number_only)

# Use the smallest D-number as the random seed
seed = min(numeric_values)

# Step 3: Set the random seed so results are reproducible across runs
random.seed(seed)

# Step 4: Generate a reproducible 128-bit AES key
key = random.getrandbits(128)

# Function provided in the assignment to convert a string into a binary string
def text_to_bits(text: str, encoding="utf-8") -> str:
    data = text.encode(encoding)
    return ''.join(f'{byte:08b}' for byte in data)

# Sort D-numbers in ascending order before building the plaintext
d_numbers.sort()

# Concatenate sorted D-numbers into a single string
sorted_d_string = ''.join(d_numbers)

# Convert the sorted D-number string to bits and take the first 128 bits
# This follows the instruction: text_to_bits(sorted-D#s)[:128]
plaintext_bits_128 = text_to_bits(sorted_d_string)[:128]

# Display the generated 128-bit plaintext block
print("Plaintext bits:", plaintext_bits_128)

# =========================================================
# PART (1): AES-128 Encryption with Round Tracing (NO HEX)
# This code encrypts a 128-bit plaintext using AES-128
# and prints the internal AES state (in bits) after each round.
# =========================================================

# ---------------------------------------------------------
# AES S-box
# ---------------------------------------------------------
# This is a fixed lookup table defined by the AES standard.
# It is used in the SubBytes step to replace each byte
# with a new value in a non-linear way.
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

# ---------------------------------------------------------
# Helper functions for AES state handling
# ---------------------------------------------------------

# Convert a 16-byte block into the AES 4x4 state matrix
# AES fills the state column by column
def bytes_to_state(b):
    return [[b[r + 4*c] for c in range(4)] for r in range(4)]

# Convert the AES state back into a single 128-bit binary string
# This is used only for printing and tracing
def state_to_bits(state):
    bits = ""
    for c in range(4):
        for r in range(4):
            bits += format(state[r][c], "08b")
    return bits

# ---------------------------------------------------------
# AES round operations
# ---------------------------------------------------------

# SubBytes: replace every byte in the state using the S-box
def sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = SBOX[state[r][c]]

# ShiftRows: shift each row left by its row index
def shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]

# Helper for MixColumns (finite field multiplication)
def xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1)

# MixColumns: mix bytes within each column to spread changes
def mix_columns(state):
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        state[0][c] = xtime(a[0]) ^ xtime(a[1]) ^ a[1] ^ a[2] ^ a[3]
        state[1][c] = a[0] ^ xtime(a[1]) ^ xtime(a[2]) ^ a[2] ^ a[3]
        state[2][c] = a[0] ^ a[1] ^ xtime(a[2]) ^ xtime(a[3]) ^ a[3]
        state[3][c] = xtime(a[0]) ^ a[0] ^ a[1] ^ a[2] ^ xtime(a[3])

# AddRoundKey: XOR the current state with the round key
def add_round_key(state, round_key):
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_key[r][c]

# ---------------------------------------------------------
# Build AES state from initialization values
# ---------------------------------------------------------

# Convert the plaintext bits into 16 bytes
plaintext_bytes = int(plaintext_bits_128, 2).to_bytes(16, 'big')

# Convert the AES key into 16 bytes
key_bytes = key.to_bytes(16, 'big')

# Create the initial AES state and round key
state = bytes_to_state(plaintext_bytes)
round_key = bytes_to_state(key_bytes)

# ---------------------------------------------------------
# Round 0: Initial AddRoundKey
# ---------------------------------------------------------
add_round_key(state, round_key)

# ---------------------------------------------------------
# Rounds 1 through 10: run full AES, print state after Round 4
# ---------------------------------------------------------
for r in range(1, 11):

    # Apply SubBytes
    sub_bytes(state)

    # Apply ShiftRows
    shift_rows(state)

    # Apply MixColumns for rounds 1–9 only
    # (AES does not use MixColumns in the final round)
    if r != 10:
        mix_columns(state)

    # Apply AddRoundKey
    add_round_key(state, round_key)

    # Print only the state after Round 4
    if r == 4:
        print("After Round 4 (bits):")
        print(state_to_bits(state))

# =========================================================
# PART (2): Flip plaintext bit 12 and count state differences
# =========================================================

def encrypt_trace_first4_rounds_bits(plaintext_bits_128, key_int):
    """
    Encrypts using the same AES round functions from Part (1)
    and returns the state (as 128-bit strings) after rounds 1–4.
    """
    # Convert inputs to bytes
    plaintext_bytes = int(plaintext_bits_128, 2).to_bytes(16, 'big')
    key_bytes = key_int.to_bytes(16, 'big')

    # Build initial state + round key
    state = bytes_to_state(plaintext_bytes)
    round_key = bytes_to_state(key_bytes)

    # Round 0 (initial AddRoundKey) — we don't compare round 0 in Part (2)
    add_round_key(state, round_key)

    # Store states after rounds 1–4
    trace = {}

    for r in range(1, 5):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_key)
        trace[r] = state_to_bits(state)  # 128-bit binary string

    return trace


def flip_bit(bitstring, bit_index):
    """
    Flips one bit in a binary string.
    bit_index is 0-based from the left (MSB side).
    """
    bits = list(bitstring)
    bits[bit_index] = '1' if bits[bit_index] == '0' else '0'
    return ''.join(bits)


def count_bit_differences(a, b):
    """Counts how many bit positions differ between two same-length bitstrings."""
    diff = 0
    for i in range(len(a)):
        if a[i] != b[i]:
            diff += 1
    return diff


# -----------------------------
# (2a) Get trace for original plaintext (Part 1)
# -----------------------------
original_trace = encrypt_trace_first4_rounds_bits(plaintext_bits_128, key)

# -----------------------------
# (2b) Flip AES bit 12 of the message
# Bit numbering: leftmost bit = 0, so bit 12 is index 12
# -----------------------------
flipped_plaintext_bits_128 = flip_bit(plaintext_bits_128, 12)

# Encrypt again and trace rounds 1–4
flipped_trace = encrypt_trace_first4_rounds_bits(flipped_plaintext_bits_128, key)

# -----------------------------
# (2c) Compare round-by-round and count how many bits differ
# -----------------------------
print("\nPart (2): Bit differences after flipping plaintext bit 12\n")
print("Round | # bits different (out of 128)")
print("------+----------------------------")

for r in range(1, 5):
    d = count_bit_differences(original_trace[r], flipped_trace[r])
    print(f"{r:>5} | {d:>26}")

