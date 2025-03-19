import tensorflow as tf
tf.compat.v1.enable_eager_execution()  # Enable eager execution

import json
import os
import sys
import numpy as np
import pandas as pd
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Embedding, LSTM, TimeDistributed, Dense
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences

from util import get_parent_directory


def load_training_data(csv_path):
    # Try reading the CSV file while skipping problematic rows
    df = pd.read_csv(csv_path, sep=',', on_bad_lines='skip')
    # Optionally, print a sample to verify the format
    # print(df.head())

    input_data = df.iloc[:, :2].astype(str).values.tolist()  # Use first 2 columns as input
    target_data = df.iloc[:, 2:].astype(str).values.tolist()  # Remaining columns as output
    return input_data, target_data

def train_rnn(csv_paths, model_name):
    tokenizer = Tokenizer()
    all_input_data, all_target_data = [], []

    for csv_path in csv_paths:
        input_data, target_data = load_training_data(csv_path)
        all_input_data.extend(input_data)
        all_target_data.extend(target_data)

    tokenizer.fit_on_texts(all_input_data + all_target_data)
    sequences_input = tokenizer.texts_to_sequences(all_input_data)
    sequences_target = tokenizer.texts_to_sequences(all_target_data)

    vocab_size = len(tokenizer.word_index) + 1
    max_length_input = max(len(seq) for seq in sequences_input)  # Input is fixed to 2 columns
    max_length_target = max(len(seq) for seq in sequences_target)  # Output can be variable length

    # Ensure y has the same sequence length as X for proper shape alignment
    max_length = max(max_length_input, max_length_target)
    X = pad_sequences(sequences_input, maxlen=max_length, padding='post')
    y = pad_sequences(sequences_target, maxlen=max_length, padding='post')
    y = np.expand_dims(y, -1)  # Ensure correct output shape

    project_path = os.path.dirname(os.path.abspath(__file__))
    parent = get_parent_directory(project_path)
    model_dir = os.path.join(parent, "Data", "Model")
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, f"{model_name}.h5")
    tokenizer_path = os.path.join(model_dir, f"{model_name}_tokenizer.json")
    header_file_path = os.path.join(model_dir, f"{model_name}_header.txt")

    if os.path.exists(model_path):
        model = load_model(model_path)
        with open(tokenizer_path, "r") as f:
            existing_tokenizer = json.load(f)
        tokenizer.word_index.update(existing_tokenizer)
    else:
        model = Sequential([
            Embedding(vocab_size, 128, input_length=max_length),
            LSTM(128, return_sequences=True),
            LSTM(128, return_sequences=True),
            TimeDistributed(Dense(vocab_size, activation='softmax'))
        ])
        model.compile(loss='sparse_categorical_crossentropy', optimizer='adam', metrics=['accuracy'])

    model.fit(X, y, epochs=2, batch_size=32, verbose=1)
    model.save(model_path)

    with open(tokenizer_path, "w") as f:
        json.dump(tokenizer.word_index, f)

    # Save the CSV headers to a text file using the first CSV file as reference
    df_header = pd.read_csv(csv_paths[0], sep=',', nrows=0)
    headers = list(df_header.columns)
    with open(header_file_path, "w") as f:
        f.write(",".join(headers))

    print(f"Model '{model_name}.h5', tokenizer '{model_name}_tokenizer.json', and header file '{model_name}_header.txt' updated and saved successfully in '{model_dir}' directory.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python train.py <csv_path_or_directory> <model_name>")
        sys.exit(1)

    csv_path = sys.argv[1]
    model_name = sys.argv[2]

    if os.path.isdir(csv_path):
        csv_files = [os.path.join(csv_path, f) for f in os.listdir(csv_path) if f.endswith(".csv")]
    else:
        csv_files = [csv_path]

    if not csv_files:
        print("No CSV files found to process.")
        sys.exit(1)

    train_rnn(csv_files, model_name)
