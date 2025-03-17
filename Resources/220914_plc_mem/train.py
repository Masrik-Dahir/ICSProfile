import numpy as np
import tensorflow as tf
from tensorflow import keras
from scapy.all import rdpcap, IP, TCP, send

# Load packets
packets = rdpcap("F:\\Repo\\ICSProfile\\Resources\\Demo\\CaptureTrafficWithTimer.pcapng")

# Extract payloads as byte sequences
payloads = []
for pkt in packets:
    if pkt.haslayer('Raw'):
        payload = pkt['Raw'].load
        payloads.append(list(payload))  # Convert bytes to list of integers

# Convert to NumPy array
max_length = max(len(p) for p in payloads)  # Find longest payload
padded_payloads = np.array([p + [0] * (max_length - len(p)) for p in payloads])  # Pad sequences

# Normalize the data (scaling bytes to range 0-1)
X = padded_payloads / 255.0

# Define RNN Model
model = keras.Sequential([
    keras.layers.LSTM(128, return_sequences=True, input_shape=(max_length, 1)),
    keras.layers.LSTM(64, return_sequences=False),
    keras.layers.Dense(128, activation="relu"),
    keras.layers.Dense(max_length, activation="sigmoid")  # Output a sequence of bytes
])

model.compile(loss="binary_crossentropy", optimizer="adam", metrics=["accuracy"])
model.summary()

# Reshape data for LSTM
X = X.reshape((X.shape[0], X.shape[1], 1))  # (samples, sequence_length, features)

# Train the model
model.fit(X, X, epochs=50, batch_size=32, validation_split=0.2)

# Generate a new sequence
random_input = np.random.rand(1, max_length, 1)  # Random seed input
generated_payload = model.predict(random_input)
generated_payload = (generated_payload * 255).astype(np.uint8)  # Convert back to byte values

print("Generated Payload:", generated_payload[0])


new_payload = bytes(generated_payload[0])  # Convert to bytes

print(new_payload)
# packet = IP(dst="192.168.1.10") / TCP(dport=502, sport=12345) / new_payload
# send(packet)