import json
import sys
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
import os


def load_models_and_tokenizers():
    model_files = [f for f in os.listdir("models") if f.endswith(".h5")]
    if not model_files:
        print("Error: No models found in the 'models' directory.")
        sys.exit(1)

    model_dict = {}
    for model_file in model_files:
        model_name = model_file.replace(".h5", "")
        model_path = f"models/{model_file}"
        tokenizer_path = f"models/{model_name}_tokenizer.json"

        if not os.path.exists(tokenizer_path):
            continue

        model = load_model(model_path)
        with open(tokenizer_path, "r") as f:
            word_index = json.load(f)

        tokenizer = Tokenizer()
        tokenizer.word_index = word_index

        model_dict[model_name] = (tokenizer, model)

    return model_dict


def predict_protocol(model_dict, new_payload):
    best_match = None
    best_score = float('-inf')

    for model_name, (tokenizer, model) in model_dict.items():
        seq = tokenizer.texts_to_sequences([new_payload])
        max_length = max(len(seq[0]), 10)
        seq = pad_sequences(seq, maxlen=max_length, padding='post')

        prediction = model.predict(seq, verbose=0)
        score = np.max(prediction)

        if score > best_score:
            best_score = score
            best_match = model_name

    return best_match if best_match else "No matching protocol found"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python match.py <modbus_payload>")
        sys.exit(1)

    new_payload = sys.argv[1]
    model_dict = load_models_and_tokenizers()
    match_result = predict_protocol(model_dict, new_payload)

    print(f"Best Matching Protocol: {match_result}")
