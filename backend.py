# --- 1. IMPORTS AND SETUP ---
import os
import hashlib
import io
import zipfile 
import json
from flask import Flask, request, render_template, send_file, jsonify # jsonify is new

from cryptography.fernet import Fernet, InvalidToken
from stegano import lsb

# --- 2. CONFIGURATION ---
# The application will store encrypted files and metadata in a local folder named 'uploads'.
UPLOAD_FOLDER = 'uploads'

# --- 3. INITIALIZE APP ---
app = Flask(__name__, template_folder='.')
app.secret_key = os.urandom(24) 

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --- 4. HELPER FUNCTIONS ---
def hash_password(password):
    """Hashes a password for secure storage and filename generation using SHA256."""
    return hashlib.sha256(password.encode()).hexdigest()

# --- 5. CORE WEB APPLICATION ROUTES ---
@app.route('/')
def index():
    """Renders the main encryption page."""
    return render_template('index.html')

@app.route('/decryption')
def decryption_page():
    """Renders the decryption page."""
    return render_template('decryption.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handles file upload from the web form."""
    try:
        files_to_share = request.files.getlist('file')
        password = request.form['password']
        key_image_file = request.files['key_image']
        
        # UPDATED: Combine user caption with your signature
        user_caption = request.form.get('caption', '').strip()
        signature = "GlyphLock by HaiCLOP's Labs\n@2025 HaiCLOP's Labs"
        
        if user_caption:
            final_caption = f"{user_caption}\n\n---\n{signature}"
        else:
            final_caption = signature

        if not files_to_share or files_to_share[0].filename == '':
            return "Error: No files selected for upload.", 400

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for file_to_share in files_to_share:
                zip_file.writestr(file_to_share.filename, file_to_share.read())
        
        zip_buffer.seek(0)
        file_content_bytes = zip_buffer.read()

        file_key = Fernet.generate_key()
        fernet = Fernet(file_key)
        encrypted_file_data = fernet.encrypt(file_content_bytes)

        password_hash = hash_password(password)
        
        # Save encrypted file locally
        encrypted_filepath = os.path.join(UPLOAD_FOLDER, f"{password_hash}.enc")
        with open(encrypted_filepath, 'wb') as f:
            f.write(encrypted_file_data)

        # Save metadata locally using the final combined caption
        metadata = {"caption": final_caption}
        metadata_filepath = os.path.join(UPLOAD_FOLDER, f"{password_hash}.meta")
        with open(metadata_filepath, 'w', encoding='utf-8') as f:
            json.dump(metadata, f)

        key_image_with_secret = lsb.hide(key_image_file, file_key.decode('latin1'))
        key_image_buffer = io.BytesIO()
        key_image_with_secret.save(key_image_buffer, "PNG")
        key_image_buffer.seek(0)
        
        return send_file(key_image_buffer, mimetype='image/png', as_attachment=True, download_name='GlyphKey.png')
        
    except Exception as e:
        print(f"An error occurred during upload: {e}")
        return "An error occurred during the upload process. Please try again.", 500

@app.route('/retrieve', methods=['POST'])
def retrieve_file():
    """Handles file retrieval from the web form."""
    try:
        password = request.form['password']
        key_image_file = request.files['key_image']
        
        password_hash = hash_password(password)
        metadata_filepath = os.path.join(UPLOAD_FOLDER, f"{password_hash}.meta")
        encrypted_filepath = os.path.join(UPLOAD_FOLDER, f"{password_hash}.enc")

        if not os.path.exists(metadata_filepath) or not os.path.exists(encrypted_filepath):
            return "Error: Invalid password or no file found.", 404
        
        with open(metadata_filepath, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
        
        caption = metadata.get('caption', '')

        try:
            extracted_key_str = lsb.reveal(key_image_file)
            if not extracted_key_str:
                raise ValueError("No hidden data found in image.")
            file_key = extracted_key_str.encode('latin1')
            fernet = Fernet(file_key)
        except Exception as e:
            return "Error: Invalid GlyphLock image or the key is corrupted.", 400

        with open(encrypted_filepath, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = fernet.decrypt(encrypted_data)
        
        decrypted_zip_buffer = io.BytesIO(decrypted_data)
        
        final_zip_buffer = io.BytesIO()
        with zipfile.ZipFile(final_zip_buffer, 'w', zipfile.ZIP_DEFLATED) as final_zip:
            final_zip.writestr('caption.txt', caption)
            with zipfile.ZipFile(decrypted_zip_buffer, 'r') as decrypted_zip:
                for filename in decrypted_zip.namelist():
                    final_zip.writestr(filename, decrypted_zip.read(filename))
        
        final_zip_buffer.seek(0)
        
        return send_file(final_zip_buffer, as_attachment=True, download_name='decrypted_package.zip', mimetype='application/zip')
        
    except InvalidToken:
        return "Error: Decryption failed. This may be due to a corrupted GlyphLock image.", 500
    except Exception as e:
        print(f"An error occurred during retrieval: {e}")
        return "An error occurred during the retrieval process. Please check your inputs.", 500

# --- 6. NEW: PUBLIC API ENDPOINTS ---

@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    """API endpoint to encrypt and store files."""
    try:
        if 'file' not in request.files or 'key_image' not in request.files:
            return jsonify({"error": "Missing 'file' or 'key_image' in request"}), 400
        if 'password' not in request.form:
            return jsonify({"error": "Missing 'password' in request form"}), 400

        files_to_share = request.files.getlist('file')
        password = request.form['password']
        key_image_file = request.files['key_image']
        
        # API version of the caption logic
        user_caption = request.form.get('caption', '').strip()
        signature = "GlyphLock by HaiCLOP's Labs\n@2025 HaiCLOP's Labs"
        
        if user_caption:
            final_caption = f"{user_caption}\n\n---\n{signature}"
        else:
            final_caption = signature

        # The core logic is identical to the web form version
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for file_to_share in files_to_share:
                zip_file.writestr(file_to_share.filename, file_to_share.read())
        zip_buffer.seek(0)
        file_content_bytes = zip_buffer.read()

        file_key = Fernet.generate_key()
        fernet = Fernet(file_key)
        encrypted_file_data = fernet.encrypt(file_content_bytes)

        password_hash = hash_password(password)
        encrypted_filepath = os.path.join(UPLOAD_FOLDER, f"{password_hash}.enc")
        with open(encrypted_filepath, 'wb') as f:
            f.write(encrypted_file_data)

        metadata = {"caption": final_caption}
        metadata_filepath = os.path.join(UPLOAD_FOLDER, f"{password_hash}.meta")
        with open(metadata_filepath, 'w', encoding='utf-8') as f:
            json.dump(metadata, f)

        key_image_with_secret = lsb.hide(key_image_file, file_key.decode('latin1'))
        key_image_buffer = io.BytesIO()
        key_image_with_secret.save(key_image_buffer, "PNG")
        key_image_buffer.seek(0)
        
        # API returns the KeyFrame image directly
        return send_file(key_image_buffer, mimetype='image/png', as_attachment=True, download_name='GlyphKey.png')

    except Exception as e:
        return jsonify({"error": f"An internal error occurred: {e}"}), 500

@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    """API endpoint to decrypt and retrieve files."""
    try:
        if 'key_image' not in request.files:
            return jsonify({"error": "Missing 'key_image' in request"}), 400
        if 'password' not in request.form:
            return jsonify({"error": "Missing 'password' in request form"}), 400

        password = request.form['password']
        key_image_file = request.files['key_image']
        
        password_hash = hash_password(password)
        metadata_filepath = os.path.join(UPLOAD_FOLDER, f"{password_hash}.meta")
        encrypted_filepath = os.path.join(UPLOAD_FOLDER, f"{password_hash}.enc")

        if not os.path.exists(metadata_filepath) or not os.path.exists(encrypted_filepath):
            return jsonify({"error": "Invalid password or no file found"}), 404
        
        with open(metadata_filepath, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
        caption = metadata.get('caption', '')

        try:
            extracted_key_str = lsb.reveal(key_image_file)
            if not extracted_key_str:
                raise ValueError("No hidden data found in image.")
            file_key = extracted_key_str.encode('latin1')
            fernet = Fernet(file_key)
        except Exception:
            return jsonify({"error": "Invalid GlyphLock image or the key is corrupted"}), 400

        with open(encrypted_filepath, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = fernet.decrypt(encrypted_data)
        
        decrypted_zip_buffer = io.BytesIO(decrypted_data)
        
        final_zip_buffer = io.BytesIO()
        with zipfile.ZipFile(final_zip_buffer, 'w', zipfile.ZIP_DEFLATED) as final_zip:
            final_zip.writestr('caption.txt', caption)
            with zipfile.ZipFile(decrypted_zip_buffer, 'r') as decrypted_zip:
                for filename in decrypted_zip.namelist():
                    final_zip.writestr(filename, decrypted_zip.read(filename))
        
        final_zip_buffer.seek(0)
        
        # API returns the decrypted zip file directly
        return send_file(final_zip_buffer, as_attachment=True, download_name='decrypted_package.zip', mimetype='application/zip')
        
    except InvalidToken:
        return jsonify({"error": "Decryption failed. Invalid password or corrupted GlyphLock."}), 500
    except Exception as e:
        return jsonify({"error": f"An internal error occurred: {e}"}), 500


# --- 7. RUN THE APP ---
if __name__ == '__main__':
    print("Starting GlyphLock Vault server...")
    app.run(debug=True, host='0.0.0.0')
