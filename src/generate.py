import os
import sys
import json
import numpy as np
import tensorflow as tf
import pandas as pd
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from util import get_parent_directory


def load_input_data(csv_path):
    """
    Reads the CSV file and returns the full DataFrame along with the first two columns as input data.
    """
    df = pd.read_csv(csv_path, sep=',', on_bad_lines='skip')
    # Use first 2 columns as input for prediction
    input_data = df.iloc[:, :2].astype(str).values.tolist()
    return df, input_data


def decode_sequence(sequence, tokenizer):
    """
    Converts a sequence of tokens back into a string using the tokenizer's index_word.
    Ignores any padding (token 0). Tokens are separated by a comma with no extra space.
    """
    words = [tokenizer.index_word.get(token, "") for token in sequence if token != 0]
    return ",".join(words)


def generate_predictions(csv_path, model_name, header_line):
    # Determine project paths and load the trained model and tokenizer
    project_path = os.path.dirname(os.path.abspath(__file__))
    parent = get_parent_directory(project_path)
    model_dir = os.path.join(parent, "Data", "Model")
    model_path = os.path.join(model_dir, f"{model_name}.h5")
    tokenizer_path = os.path.join(model_dir, f"{model_name}_tokenizer.json")

    model = load_model(model_path)
    with open(tokenizer_path, "r") as f:
        word_index = json.load(f)

    # Build a tokenizer instance with the saved word index.
    tokenizer = Tokenizer()
    tokenizer.word_index = word_index
    # Create a reverse lookup for decoding
    tokenizer.index_word = {idx: word for word, idx in word_index.items()}

    # Load the full input data and the DataFrame with all columns
    original_df, input_data = load_input_data(csv_path)

    # Convert the input data to sequences using only the first 2 columns
    sequences = tokenizer.texts_to_sequences(input_data)
    # Use the model's expected input length for padding
    max_length = model.input_shape[1]
    X = pad_sequences(sequences, maxlen=max_length, padding='post')

    # Predict the output using the model
    predictions = model.predict(X)
    # predictions shape: (num_samples, max_length, vocab_size)

    guessed_payloads = []
    for i, pred in enumerate(predictions):
        # For each time step, choose the token with the highest probability.
        guessed_tokens = np.argmax(pred, axis=1)
        # Decode the token sequence into text.
        guessed_text = decode_sequence(guessed_tokens, tokenizer)
        guessed_payloads.append(guessed_text)

        # Compute average confidence for the prediction and print it.
        avg_confidence = np.mean(np.max(pred, axis=1))
        print(f"Sample {i + 1} Confidence: {avg_confidence:.4f}")

    # Append the guessed payload column to the original DataFrame.
    original_df['guessed_values'] = guessed_payloads

    # Create a Predict directory relative to the CSV file's directory
    csv_dir = os.path.dirname(csv_path)
    parent = get_parent_directory(project_path)
    predict_dir = os.path.join(parent, "Data", "Predict")
    os.makedirs(predict_dir, exist_ok=True)

    # Build output file path using the base file name of the CSV file.
    base_name = os.path.splitext(os.path.basename(csv_path))[0]
    file_name = f"{base_name}.csv"
    output_file = os.path.join(predict_dir, file_name)

    # Write CSV file using the header line from the header file as the first line.
    with open(output_file, "w", newline='') as f:
        f.write(header_line + "\n")
        for row in original_df.itertuples(index=False):
            row_str = ",".join(str(item).strip() for item in row)
            f.write(row_str + "\n")

    print(f"Output with guessed column written to {output_file}")


if __name__ == "__main__":
    # Determine input parameters
    if len(sys.argv) >= 3:
        csv_path = sys.argv[1]
        model_name = sys.argv[2]
    else:
        csv_path = input("Enter the CSV path: ").strip()
        model_name = input("Enter the model name: ").strip()

    # Compute the model directory to locate the header file
    project_path = os.path.dirname(os.path.abspath(__file__))
    parent = get_parent_directory(project_path)
    model_dir = os.path.join(parent, "Data", "Model")

    # Construct header file path in the model directory (e.g. abc_header.txt)
    header_file_path = os.path.join(model_dir, f"{model_name}_header.txt")
    if not os.path.exists(header_file_path):
        raise FileNotFoundError(f"Header file {header_file_path} not found.")

    # Read only the first line from the header file
    with open(header_file_path, "r") as f:
        header_line = f.readline().strip()

    # Optionally, print the header line to verify it
    print("Using header line for output file:")
    print(header_line)
    print("=" * 80)

    # If the input path is a directory, process all CSV files in the directory.
    if os.path.isdir(csv_path):
        for file in os.listdir(csv_path):
            if file.lower().endswith(".csv"):
                file_path = os.path.join(csv_path, file)
                print(f"Processing file: {file_path}")
                generate_predictions(file_path, model_name, header_line)
    else:
        # Process a single CSV file
        generate_predictions(csv_path, model_name, header_line)
