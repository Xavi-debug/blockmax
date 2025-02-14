from flask import Flask, request, jsonify, render_template
import requests
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
VT_API_KEY = 'TU_API_KEY_AQUI'
VT_URL = 'https://www.virustotal.com/api/v3/files'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)
    
    # Subir a VirusTotal
    headers = {'x-apikey': VT_API_KEY}
    with open(file_path, 'rb') as f:
        files = {'file': (file.filename, f)}
        response = requests.post(VT_URL, headers=headers, files=files)
    
    return jsonify(response.json())

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
