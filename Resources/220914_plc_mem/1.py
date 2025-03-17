import scapy.all as scapy
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import SimpleRNN, Dense, Embedding
import numpy as np

# Load the PCAP file
pcap_file = "F:\\Repo\\ICSProfile\\Resources\\Demo\\CaptureTrafficWithTimer.pcapng"
packets = scapy.rdpcap(pcap_file)

# Analyze packets to extract payload data
def extract_payloads(packets):
    payloads = []
    for packet in packets:
        try:
            if packet.haslayer(scapy.Raw):
                payloads.append(packet[scapy.Raw].load.hex())  # Convert payload to hex string
        except IndexError:  # Handle packets without a payload or unexpected layers
            continue
    return payloads

payloads = extract_payloads(packets)

# Tokenize hexadecimal payloads
tokenizer = Tokenizer(char_level=True)
tokenizer.fit_on_texts(payloads)
sequences = tokenizer.texts_to_sequences(payloads)
data = pad_sequences(sequences, padding='post', maxlen=256)  # Adjust maxlen according to your data

# Prepare labels (for this example, let's assume binary classification with dummy labels)
labels = np.random.randint(0, 2, size=(len(data),))

# Define an RNN model
model = Sequential([
    Embedding(input_dim=len(tokenizer.word_index) + 1, output_dim=64, input_length=256),  # Adjust embedding layer
    SimpleRNN(128, return_sequences=True),
    SimpleRNN(128),
    Dense(1, activation='sigmoid')
])

model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Train the model
model.fit(data, labels, epochs=50, batch_size=64)

# Save the model and tokenizer
model.save('packet_model.h5')
tokenizer_json = tokenizer.to_json()
with open('tokenizer.json', 'w') as file:
    file.write(tokenizer_json)
