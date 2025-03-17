import numpy as np
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
from itertools import product
from scapy.all import IP, TCP, Raw, send

def create_adjusted_hex_tokenizer():
    """Create a tokenizer that fits within the model's embedding index range."""
    hex_digits = '0123456789ABCDEF'
    valid_range = 17  # max index is 17, i.e., 0-17 inclusive
    tokens = {}
    for i, (a, b) in enumerate(product(hex_digits, repeat=2)):
        index = i + 1
        if index > valid_range:
            break
        tokens[f'{a}{b}'] = index
    return tokens

def hex_payload_to_sequence(payload, tokenizer):
    """Convert hex payload to sequence of integers using the tokenizer."""
    sequence = []
    for i in range(0, len(payload), 2):
        byte = payload[i:i+2].upper()
        if byte in tokenizer:
            sequence.append(tokenizer[byte])
        else:
            sequence.append(0)  # use 0 for unknown/out-of-range bytes
    return sequence

# Load the RNN model
model = load_model('F:\\Repo\\ICSProfile\\Resources\\220914_plc_mem\\packet_model.h5')

# Create an adjusted tokenizer
tokenizer = create_adjusted_hex_tokenizer()

# Convert payload to sequence
hex_payload = "030300140000"
sequence = hex_payload_to_sequence(hex_payload, tokenizer)

# Pad the sequence to match the model's input requirements
max_len = 256  # Match this value with your training setup
padded_sequence = pad_sequences([sequence], maxlen=max_len)

# Predict using the model
prediction = model.predict(padded_sequence)
print("Model Prediction (raw):", prediction)
