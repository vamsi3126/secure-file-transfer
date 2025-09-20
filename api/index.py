from flask import Flask, request, render_template, send_file, jsonify
import os
import random
import string
from datetime import datetime, timedelta
import hashlib
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from functools import wraps
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = "/tmp/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['MAX_CONTENT_LENGTH'] = 150 * 1024 * 1024  # 150MB limit

# In-memory storage
rate_limit_data = {}
failed_attempts_data = {}
blocked_ips = {}
file_data = {}

RATE_LIMIT_WINDOW = 3600  # 1 hour in seconds
MAX_REQUESTS = 100  # Maximum requests per hour
BLOCK_DURATION = 1800  # 30 minutes in seconds
MAX_FAILED_ATTEMPTS = 10  # Maximum failed attempts before blocking

# Rate limiting decorator
def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr or request.headers.get('X-Forwarded-For', '127.0.0.1')
        
        # Check if IP is blocked
        if ip in blocked_ips and blocked_ips[ip] > datetime.now():
            return jsonify({"error": "Too many failed attempts. Please try again later."}), 429
        
        # Get current request count from memory
        if ip not in rate_limit_data:
            rate_limit_data[ip] = {
                'count': 1,
                'expires': datetime.now() + timedelta(seconds=RATE_LIMIT_WINDOW)
            }
        elif rate_limit_data[ip]['expires'] < datetime.now():
            rate_limit_data[ip] = {
                'count': 1,
                'expires': datetime.now() + timedelta(seconds=RATE_LIMIT_WINDOW)
            }
        elif rate_limit_data[ip]['count'] >= MAX_REQUESTS:
            return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429
        else:
            rate_limit_data[ip]['count'] += 1
        
        return f(*args, **kwargs)
    return decorated_function

# Track failed attempts
def track_failed_attempt(ip):
    if ip not in failed_attempts_data:
        failed_attempts_data[ip] = {
            'count': 1,
            'expires': datetime.now() + timedelta(seconds=BLOCK_DURATION)
        }
    elif failed_attempts_data[ip]['expires'] < datetime.now():
        failed_attempts_data[ip] = {
            'count': 1,
            'expires': datetime.now() + timedelta(seconds=BLOCK_DURATION)
        }
    else:
        failed_attempts_data[ip]['count'] += 1
    
    if failed_attempts_data[ip]['count'] >= MAX_FAILED_ATTEMPTS:
        blocked_ips[ip] = datetime.now() + timedelta(seconds=BLOCK_DURATION)
        return True
    return False

# Generate an alphanumeric 6-character code
def generate_pin():
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choices(characters, k=6))

# Derive encryption key from PIN
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
@rate_limit
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file selected"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    try:
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
            "warning": "Download immediately - files expire in 24 hours or if server restarts"
        })

    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return jsonify({"error": f"Upload failed: {str(e)}"}), 500

@app.route("/download", methods=["POST"])
@rate_limit
def download_file():
    code = request.form.get("code", "").strip()
    key = request.form.get("key", "").strip()
    ip = request.remote_addr or request.headers.get('X-Forwarded-For', '127.0.0.1')

    if not code or not key:
        return render_template("index.html", error="Both code and key are required")

    if code not in file_data:
        if track_failed_attempt(ip):
            return render_template("index.html", error="Too many failed attempts. Please try again later.")
        return render_template("index.html", error="Invalid access code")

    if key != file_data[code]["key"]:
        if track_failed_attempt(ip):
            return render_template("index.html", error="Too many failed attempts. Please try again later.")
        return render_template("index.html", error="Invalid decryption key")

    try:
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
        logger.error(f"Download error: {str(e)}")
        return render_template("index.html", error=f"Download failed: {str(e)}")

# Vercel handler
def handler(request):
    return app(request.environ, lambda *args: None)