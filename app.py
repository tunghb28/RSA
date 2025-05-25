from flask import Flask, request, jsonify, send_file, render_template, send_from_directory
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
import os
import base64
import json
from werkzeug.utils import secure_filename
import shutil

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SIGNED_FOLDER'] = 'signed_files'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Tạo thư mục uploads và signed_files nếu chưa tồn tại
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['SIGNED_FOLDER'], exist_ok=True)

@app.route('/')
def index():
    """Trang chủ"""
    return render_template('index.html')

def generate_key_pair():
    """Sinh cặp khóa RSA"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # Lưu private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Lưu public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem

def sign_file(file_path, private_key):
    """Ký số file"""
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    # Tạo chữ ký
    private_key = load_pem_private_key(private_key, password=None)
    signature = private_key.sign(
        file_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return base64.b64encode(signature).decode()

def verify_signature(file_path, signature, public_key):
    """Xác thực chữ ký"""
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    try:
        public_key = load_pem_public_key(public_key)
        signature = base64.b64decode(signature)
        
        public_key.verify(
            signature,
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False

@app.route('/generate-keys', methods=['POST'])
def generate_keys():
    """API endpoint để sinh cặp khóa"""
    try:
        private_key, public_key = generate_key_pair()
        return jsonify({
            'private_key': private_key.decode(),
            'public_key': public_key.decode()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/sign-file', methods=['POST'])
def sign_file_endpoint():
    """API endpoint để ký số file"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    if 'private_key' not in request.form:
        return jsonify({'error': 'No private key provided'}), 400
    
    file = request.files['file']
    private_key = request.form['private_key'].encode()
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        signature = sign_file(file_path, private_key)
        
        # Tạo file đã ký
        signed_filename = f"signed_{filename}"
        signed_file_path = os.path.join(app.config['SIGNED_FOLDER'], signed_filename)
        
        # Copy file gốc và thêm chữ ký vào cuối file
        shutil.copy2(file_path, signed_file_path)
        with open(signed_file_path, 'ab') as f:
            f.write(b'\n---SIGNATURE---\n')
            f.write(signature.encode())
        
        return jsonify({
            'filename': filename,
            'signed_filename': signed_filename,
            'signature': signature
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/verify-signature', methods=['POST'])
def verify_signature_endpoint():
    """API endpoint để xác thực chữ ký"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    if 'signature' not in request.form:
        return jsonify({'error': 'No signature provided'}), 400
    
    if 'public_key' not in request.form:
        return jsonify({'error': 'No public key provided'}), 400
    
    file = request.files['file']
    signature = request.form['signature']
    public_key = request.form['public_key'].encode()
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        is_valid = verify_signature(file_path, signature, public_key)
        
        return jsonify({
            'filename': filename,
            'is_valid': is_valid
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download/<filename>')
def download_file(filename):
    """API endpoint để tải file đã ký"""
    try:
        return send_from_directory(app.config['SIGNED_FOLDER'], filename, as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/list-files')
def list_files():
    """API endpoint để lấy danh sách file đã upload"""
    try:
        files = []
        for filename in os.listdir(app.config['UPLOAD_FOLDER']):
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.isfile(file_path):
                files.append({
                    'name': filename,
                    'size': os.path.getsize(file_path),
                    'modified': os.path.getmtime(file_path)
                })
        return jsonify({'files': files})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True) 