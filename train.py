import json
import sys
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import SimpleRNN, Dense, Embedding
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
import os

payloads = []

# Function to extract UMAS function code and payload while keeping function code in hex
def extract_umas_function_code_and_payload_hex(data):
    raw_bytes = bytes.fromhex(data.replace(":", ""))
    length = len(raw_bytes)

    # UMAS function code is typically byte 9 (payload[1]) after the Modbus PDU
    umas_function_code = raw_bytes[9] if length >= 10 else None

    # Format function code in hex
    umas_function_code_hex = f"0x{umas_function_code:02X}" if umas_function_code is not None else "N/A"

    # Extract payload (everything after Modbus header and UMAS function code)
    payload = raw_bytes[10:] if length > 10 else b""

    formatted_payload = ' '.join(f"{byte:02X}" for byte in payload)

    return umas_function_code_hex, formatted_payload


def extract_modbus_data(json_path, function_code):
    with open(json_path, 'r') as json_file:
        data = json.load(json_file)

    for packet in data:
        if 'modbus' in packet and 'func_code' in packet['modbus'] and str(packet['modbus']['func_code']) == str(
                function_code):
            if 'data' in packet['modbus']:
                payloads.append(packet['modbus']['data'])

    return payloads


def train_rnn(payloads, model_name):
    tokenizer = Tokenizer()
    tokenizer.fit_on_texts(payloads)
    sequences = tokenizer.texts_to_sequences(payloads)
    vocab_size = len(tokenizer.word_index) + 1

    max_length = max(len(seq) for seq in sequences)
    sequences = pad_sequences(sequences, maxlen=max_length, padding='post')

    X = sequences[:, :-1]
    y = sequences[:, -1]

    y = tf.keras.utils.to_categorical(y, num_classes=vocab_size)

    model = Sequential([
        Embedding(vocab_size, 10, input_length=max_length - 1),
        SimpleRNN(50, return_sequences=True),
        SimpleRNN(50),
        Dense(vocab_size, activation='softmax')
    ])

    model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
    model.fit(X, y, epochs=50, verbose=0)

    os.makedirs("models", exist_ok=True)
    model.save(f"models/{model_name}.h5")
    with open(f"models/{model_name}_tokenizer.json", "w") as f:
        json.dump(tokenizer.word_index, f)

    print(f"Model '{model_name}.h5' trained and saved successfully in 'models/' directory.")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python train.py <json_directory> <function_code> <model_name>")
        sys.exit(1)

    json_path = sys.argv[1]
    function_code = sys.argv[2]
    model_name = sys.argv[3]

    modbus_data = extract_modbus_data(json_path, function_code)

    if modbus_data:
        train_rnn(modbus_data, model_name)
    else:
        print(f"No Modbus data found for function code {function_code}.")

    # Process data for UMAS function codes
    processed_data = []
    for modbus_data in payloads:
        umas_function_code, payload = extract_umas_function_code_and_payload(modbus_data)
        processed_data.append(f"{modbus_data},UMAS,{umas_function_code},{payload}")

    # Save as a CSV text file with comma-separated values
    txt_path_umas = "./umas_function_analysis.txt"

    # Write to file
    with open(txt_path_umas, "w") as file:
        file.write("Modbus Data,Protocol,UMAS Function Code,Payload\n")  # Header
        file.write("\n".join(processed_data))  # Data

    # Return file path for download
    txt_path_umas
