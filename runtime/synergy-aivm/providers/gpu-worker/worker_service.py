import os
import hashlib
import numpy as np
from PIL import Image
import onnxruntime as ort

# --- Configuration ---
MODEL_PATH = "../../samples/simple-inference/efficientnet-lite4-11.onnx"
LABELS_PATH = "../../samples/simple-inference/imagenet_classes.txt"
IMAGE_PATH = "path/to/your/image.jpg"  # <-- replace with your input image path

# --- Load ImageNet labels ---
with open(LABELS_PATH, "r") as f:
    labels = [line.strip() for line in f.readlines()]

# --- Load ONNX model ---
session = ort.InferenceSession(MODEL_PATH)
print(f"Model {MODEL_PATH} loaded successfully")

# --- Preprocess image ---
img = Image.open(IMAGE_PATH).convert("RGB").resize((224, 224))
img_array = np.array(img).astype(np.float32) / 255.0  # normalize to [0,1]
img_array = img_array.transpose(2, 0, 1)  # HWC -> CHW
img_array = np.expand_dims(img_array, axis=0)  # add batch dimension

# --- Run inference ---
input_name = session.get_inputs()[0].name
outputs = session.run(None, {input_name: img_array})

# --- Postprocess result ---
predicted_index = np.argmax(outputs[0])
predicted_label = labels[predicted_index]
confidence = float(np.max(outputs[0]))

# --- Transcript hash for logging/auditing ---
transcript = f"Image: {IMAGE_PATH}, Predicted: {predicted_label}, Confidence: {confidence:.4f}"
transcript_hash = hashlib.sha256(transcript.encode()).hexdigest()

# --- Output ---
print(f"Inference result: {predicted_label} ({confidence:.4f})")
print(f"Transcript hash: {transcript_hash}")
