import random

# Step 1: List all group members' D-numbers (keep the 'D' as required)
d_numbers = [
    "D12932087",
    "D39061508"
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
