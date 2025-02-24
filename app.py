from flask import Flask, request, jsonify, render_template
import requests
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
VT_API_KEY = 'TU_API_KEY_AQUI'
VT_URL = 'https://www.virustotal.com/api/v3/files'
MAGIC_LOOPS_URL = 'https://magicloops.dev/api/loop/3af2db23-4607-43c2-a33f-c484387d7397/run'

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

@app.route('/analisis-seguridad', methods=['POST'])
def analisis_seguridad():
    # Obtén el payload enviado en la solicitud
    data = request.get_json()
    
    # Prepara los headers para la solicitud
    headers = {'Content-Type': 'application/json'}
    
    try:
        # Realiza la solicitud POST a la API de Magic Loops
        response = requests.post(MAGIC_LOOPS_URL, json=data, headers=headers)
        response.raise_for_status()  # Genera una excepción si hay error en la respuesta
        return jsonify(response.json())
    except Exception as e:
        print("Error al conectar con Magic Loops:", e)
        return jsonify({
            "error": "Error al conectar con Magic Loops",
            "details": str(e)
        }), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
