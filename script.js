function uploadFile() {
    let fileInput = document.getElementById('fileInput');
    if (fileInput.files.length === 0) {
        alert('Por favor, selecciona un archivo.');
        return;
    }
    let file = fileInput.files[0];
    let formData = new FormData();
    formData.append('file', file);

    fetch('/upload', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('result').innerText = 'Resultado: ' + JSON.stringify(data, null, 2);
    })
    .catch(error => console.error('Error:', error));
}
