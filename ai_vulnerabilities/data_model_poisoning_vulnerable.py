"""
Test cases for data and model poisoning vulnerabilities.
Targets rules in rules/ai/data_model_poisoning.yml.
For security scanner testing only.
"""
import pickle


# ---------------------------------------------------------------------------
# Vulnerable patterns
# ---------------------------------------------------------------------------

def vulnerable_pickle_model_load():
    """Loading a model via pickle from an untrusted path enables arbitrary
    code execution during deserialization."""
    model_path = "/tmp/uploaded_model.pkl"
    model = pickle.load(open(model_path, "rb"))
    return model


def vulnerable_torch_load_untrusted():
    """torch.load uses pickle internally; loading an untrusted checkpoint
    can execute arbitrary code."""
    import torch
    model_path = "/shared/models/user_model.pt"
    model = torch.load(model_path)
    return model


def vulnerable_huggingface_user_model():
    """Loading a HuggingFace model from user-controlled input opens the
    door to model poisoning attacks."""
    from transformers import AutoModel
    user_model_name = input("Enter model name: ")
    model = AutoModel.from_pretrained(user_model_name)
    return model


def vulnerable_huggingface_user_tokenizer():
    """User-controlled tokenizer identifier can load a trojanised
    tokenizer from the Hub."""
    from transformers import AutoTokenizer
    user_tokenizer = input("Enter tokenizer name: ")
    tokenizer = AutoTokenizer.from_pretrained(user_tokenizer)
    return tokenizer


def vulnerable_joblib_load():
    """joblib.load can execute arbitrary code from untrusted files, just
    like pickle."""
    import joblib
    user_path = "/uploads/model.joblib"
    model = joblib.load(user_path)
    return model


def vulnerable_tensorflow_load_untrusted():
    """Loading a TensorFlow SavedModel from an untrusted path can execute
    malicious ops embedded in the model graph."""
    import tensorflow as tf
    user_path = "/tmp/uploaded_tf_model"
    model = tf.saved_model.load(user_path)
    return model


# ---------------------------------------------------------------------------
# Safe patterns
# ---------------------------------------------------------------------------

def safe_torch_load_weights_only():
    """Use weights_only=True to prevent arbitrary code execution during
    deserialization."""
    import torch
    model_path = "/verified/models/model.pt"
    model = torch.load(model_path, weights_only=True)
    return model


def safe_huggingface_model_allowlist():
    """Validate model identifier against an allowlist before loading."""
    from transformers import AutoModel
    ALLOWED_MODELS = {"bert-base-uncased", "distilbert-base-uncased"}
    model_name = input("Enter model name: ")
    if model_name not in ALLOWED_MODELS:
        raise ValueError(f"Model '{model_name}' is not in the trusted allowlist")
    model = AutoModel.from_pretrained(model_name)
    return model


def safe_safetensors_format():
    """Use the safetensors format which does not allow code execution."""
    from safetensors.torch import load_file
    tensors = load_file("/verified/models/model.safetensors")
    return tensors
