from flask import Flask, request, render_template, send_file, jsonify
import os
import random
import string
from datetime import datetime, timedelta
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

app = Flask(__name__, template_folder='../../templates')

# Configuration
UPLOAD_FOLDER = "/tmp/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# In-memory storage
file_data = {}

def generate_pin():
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choices(characters, k=6))

def derive_key(pin):
    salt = b"unique_salt_value"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(pin.encode()))

@app.route("/")
def upload_form():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file selected"}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400

        access_code = generate_pin()
        decryption_key = generate_pin()
        
        file_data_bytes = file.read()
        file_size_mb = round(len(file_data_bytes) / (1024 * 1024), 2)
        
        derived_key = derive_key(decryption_key)
        cipher = Fernet(derived_key)
        encrypted_data = cipher.encrypt(file_data_bytes)

        filename = file.filename
        encrypted_file_path = os.path.join(UPLOAD_FOLDER, f"{filename}.enc")
        with open(encrypted_file_path, "wb") as f:
            f.write(encrypted_data)

        file_data[access_code] = {
            "path": encrypted_file_path,
            "key": decryption_key,
            "filename": filename,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "size_mb": file_size_mb
        }

        return jsonify({
            "success": True,
            "file": filename,
            "size_mb": file_size_mb,
            "code": access_code,
            "key": decryption_key,
            "warning": "Download immediately - files expire in 24 hours"
        })

    except Exception as e:
        return jsonify({"error": f"Upload failed: {str(e)}"}), 500

@app.route("/download", methods=["POST"])
def download_file():
    try:
        code = request.form.get("code", "").strip()
        key = request.form.get("key", "").strip()

        if not code or not key:
            return render_template("index.html", error="Both code and key are required")

        if code not in file_data:
            return render_template("index.html", error="Invalid access code")

        if key != file_data[code]["key"]:
            return render_template("index.html", error="Invalid decryption key")

        encrypted_file_path = file_data[code]["path"]
        if not os.path.exists(encrypted_file_path):
            return render_template("index.html", error="File expired or deleted")

        derived_key = derive_key(key)
        cipher = Fernet(derived_key)
        
        with open(encrypted_file_path, "rb") as f:
            decrypted_data = cipher.decrypt(f.read())

        temp_path = os.path.join(UPLOAD_FOLDER, file_data[code]["filename"])
        with open(temp_path, "wb") as f:
            f.write(decrypted_data)

        response = send_file(
            temp_path,
            as_attachment=True,
            download_name=file_data[code]["filename"]
        )
        
        @response.call_on_close
        def cleanup():
            try:
                os.remove(temp_path)
            except:
                pass
                
        return response

    except Exception as e:
        return render_template("index.html", error=f"Download failed: {str(e)}")

# Vercel entry point
def handler(request):
    return app(request.environ, lambda *args: None)