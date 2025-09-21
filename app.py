from flask import Flask, request, render_template, send_file, redirect, url_for
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import io

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# NOTE: For demo/testing we use a single random key at startup.
# For real projects, use proper key management (KMS, environment vars, etc.)
KEY = get_random_bytes(32)  # AES-256

def encrypt_bytes(plain_bytes: bytes) -> bytes:
    cipher = AES.new(KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plain_bytes)
    return cipher.nonce + tag + ciphertext  # nonce(16) + tag(16) + ciphertext

def decrypt_bytes(encrypted: bytes) -> bytes:
    nonce = encrypted[:16]
    tag = encrypted[16:32]
    ciphertext = encrypted[32:]
    cipher = AES.new(KEY, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        if "file" not in request.files:
            return "No file field in form", 400
        file = request.files["file"]
        if file and file.filename:
            safe_name = secure_filename(file.filename)
            data = file.read()
            encrypted = encrypt_bytes(data)
            dest_path = os.path.join(app.config["UPLOAD_FOLDER"], safe_name + ".enc")
            with open(dest_path, "wb") as f:
                f.write(encrypted)
            # redirect so the page reloads and shows the file list
            return redirect(url_for("index"))
        else:
            return "No file selected", 400

    # GET -> list available .enc files
    files = sorted([f for f in os.listdir(app.config["UPLOAD_FOLDER"]) if f.endswith(".enc")])
    return render_template("index.html", files=files)

@app.route("/download/<path:filename>")
def download(filename):
    # filename should be the exact .enc file name shown in the UI
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    if not os.path.exists(filepath):
        return "File not found", 404
    try:
        with open(filepath, "rb") as f:
            encrypted = f.read()
        decrypted = decrypt_bytes(encrypted)
    except Exception as e:
        return f"Failed to decrypt file: {e}", 500

    # return file from memory
    original_name = filename[:-4] if filename.endswith(".enc") else ("decrypted_" + filename)
    bio = io.BytesIO(decrypted)
    bio.seek(0)
    return send_file(bio, as_attachment=True, download_name=original_name)

if __name__ == "__main__":
    app.run(debug=True)
