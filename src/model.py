import json
import os
import sys
import numpy as np
import tensorflow as tf
import pandas as pd
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import SimpleRNN, Dense, Embedding
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences


def load_training_data(csv_path):
    """
    Loads and processes training data from a CSV file. The data is split into input data
    and target data based on the columns of the CSV. Input data comprises the first three
    columns: ParentProtocol, ParentData, and ParentFunctionCode, while target data
    comprises the remaining columns starting from the fourth column onward. All data
    is converted to a list of strings for compatibility with downstream processes.

    :param csv_path: Path to the CSV file containing the training data.
    :type csv_path: str
    :return: A tuple containing two lists. The first list represents the input data extracted
        from the first three columns of the CSV, and the second list represents the target
        data extracted from the remaining columns of the CSV.
    :rtype: tuple[list[list[str]], list[list[str]]]
    """
    df = pd.read_csv(csv_path)
    input_data = df.iloc[:, :3].astype(str).values.tolist()  # ParentProtocol, ParentData, ParentFunctionCode
    target_data = df.iloc[:, 3:].astype(str).values.tolist()  # TargetFunctionCode, TargetPayload, ...
    return input_data, target_data


def apply_weighting(sequences_input):
    """
    Applies a weighting strategy to each sequence in the provided input by increasing the weight
    of specific sequence positions. The method modifies sequences of length 3 or greater by
    repeating the first and third elements three times, while keeping other positions unchanged.
    In case of sequences shorter than 3, they remain unmodified. The processed sequences are
    collected and returned as a list.

    :param sequences_input: A list of sequences represented as strings. Each sequence is processed to
        apply specific weighting rules or left unchanged if its length is less than 3.
    :type sequences_input: list[str]

    :return: A list of processed sequences where weighted elements replaced certain positions
        depending on the sequence's length and defined rules.
    :rtype: list[str]
    """
    weighted_sequences = []
    for seq in sequences_input:
        if len(seq) >= 3:
            weighted_seq = seq[:1] * 3 + seq[1:2] + seq[2:3] * 3 + seq[
                                                                   3:]  # Higher weight on ParentProtocol and ParentFunctionCode
        else:
            weighted_seq = seq  # In case of incomplete sequences
        weighted_sequences.append(weighted_seq)
    return weighted_sequences


def train_rnn(csv_path, model_name="persistent_model"):
    """
    Trains a Recurrent Neural Network (RNN) model on the given dataset specified as
    a CSV file. The method preprocesses input and target sequences, applies sequence
    weighting, tokenizes the text, and pads the sequences to prepare them for training.
    It either updates an existing model or creates and saves a new one along with its tokenizer.

    :param csv_path: Path to the CSV file containing training data.
    :type csv_path: str
    :param model_name: Name for saving the model and its tokenizer. Defaults to "persistent_model".
    :type model_name: str, optional
    :return: None
    """
    input_data, target_data = load_training_data(csv_path)

    tokenizer = Tokenizer()
    tokenizer.fit_on_texts(input_data + target_data)
    sequences_input = tokenizer.texts_to_sequences(input_data)
    sequences_target = tokenizer.texts_to_sequences(target_data)

    sequences_input = apply_weighting(sequences_input)  # Apply weighting to input sequences

    vocab_size = len(tokenizer.word_index) + 1
    max_length = max(len(seq) for seq in sequences_input + sequences_target)

    X = pad_sequences(sequences_input, maxlen=max_length, padding='post')
    y = pad_sequences(sequences_target, maxlen=max_length, padding='post')
    y = tf.keras.utils.to_categorical(y, num_classes=vocab_size)

    model_path = f"models/{model_name}.h5"
    tokenizer_path = f"models/{model_name}_tokenizer.json"

    if os.path.exists(model_path):
        model = load_model(model_path)
        with open(tokenizer_path, "r") as f:
            existing_tokenizer = json.load(f)
        tokenizer.word_index.update(existing_tokenizer)
    else:
        model = Sequential([
            Embedding(vocab_size, 10, input_length=max_length),
            SimpleRNN(50, return_sequences=True),
            SimpleRNN(50),
            Dense(vocab_size, activation='softmax')
        ])
        model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])

    model.fit(X, y, epochs=50, verbose=0)

    os.makedirs("models", exist_ok=True)
    model.save(model_path)
    with open(tokenizer_path, "w") as f:
        json.dump(tokenizer.word_index, f)

    print(f"Model '{model_name}.h5' updated and saved successfully in 'models/' directory.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python train.py <csv_path>")
        sys.exit(1)

    csv_path = sys.argv[1]
    train_rnn(csv_path)
