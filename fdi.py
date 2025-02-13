import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import threading
import logging
from scapy.all import *
import psutil
import yara
import os
import time
from collections import defaultdict
from PIL import Image, ImageTk  # Para manejar imágenes

class SecurityMonitor:
    def __init__(self, gui):
        self.gui = gui
        self.attack_threshold = 100  # Umbral de paquetes por segundo
        self.connection_count = defaultdict(int)
        self.blocked_ips = set()
        self.logger = self._setup_logger()
        self.yara_rules = yara.compile('rules.yar')  # Compilar reglas YARA una vez
        self.scanning = False

    def _setup_logger(self):
        logger = logging.getLogger('SecurityMonitor')
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler('security.log')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def analyze_packet(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            self.connection_count[src_ip] += 1
            if self.connection_count[src_ip] > self.attack_threshold:
                self.handle_potential_attack(src_ip)

    def handle_potential_attack(self, ip):
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            self.logger.warning(f"Posible ataque DoS detectado desde {ip}")
            self.gui.update_log(f"⚠️ Posible ataque DoS detectado desde {ip}")
            self.apply_firewall_rule(ip)

    def apply_firewall_rule(self, ip):
        try:
            if os.name == 'posix':
                os.system(f'iptables -A INPUT -s {ip} -j DROP')
            elif os.name == 'nt':
                os.system(f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}')
            self.logger.info(f"IP {ip} bloqueada en el firewall")
            self.gui.update_log(f"✅ IP {ip} bloqueada en el firewall")
        except Exception as e:
            self.logger.error(f"Error al aplicar regla de firewall: {e}")
            self.gui.update_log(f"❌ Error al aplicar regla de firewall: {e}")

    def scan_files(self, path):
        try:
            for root, _, files in os.walk(path):
                for file in files:
                    full_path = os.path.join(root, file)
                    try:
                        matches = self.yara_rules.match(full_path)
                        if matches:
                            mensaje = f"⚠️ Malware detectado en {full_path} | Coincidencias: {matches}"
                            self.logger.warning(mensaje)
                            self.gui.update_log(mensaje)
                    except yara.Error as e:
                        self.gui.update_log(f"Error analizando {full_path}: {e}")
        except Exception as e:
            self.gui.update_log(f"Error en escaneo de archivos: {e}")

    def monitor_system(self):
        while True:
            cpu_percent = psutil.cpu_percent()
            memory_percent = psutil.virtual_memory().percent
            if cpu_percent > 90 or memory_percent > 90:
                self.gui.update_log(f"⚠️ Alto uso de recursos - CPU: {cpu_percent}%, Memoria: {memory_percent}%")
            time.sleep(5)

    def start_network_monitoring(self):
        try:
            self.gui.update_log("🛡️ Iniciando monitorización de red...")
            sniff(prn=self.analyze_packet, store=0)
        except Exception as e:
            self.gui.update_log(f"❌ Error en la captura de paquetes: {e}")

class SecurityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("BlockMax - Sistema de Defensa")
        self.root.configure(bg="#1e1e1e")  # Fondo oscuro
        self.monitor = SecurityMonitor(self)
        self.scan_path = ""

        # Estilos personalizados
        style = ttk.Style()
        style.configure("TButton", font=("Arial", 12, "bold"), padding=10)
        style.configure("TLabel", font=("Arial", 14), background="#1e1e1e", foreground="white")
        
        # Cargar y mostrar el logo
        image = Image.open("logo.png")
        image = image.resize((150, 150), Image.LANCZOS)
        self.logo = ImageTk.PhotoImage(image)
        self.logo_label = ttk.Label(root, image=self.logo, background="#1e1e1e")
        self.logo_label.pack(pady=10)

        self.status_label = ttk.Label(root, text="Estado: Seguro", font=("Arial", 16, "bold"), background="#1e1e1e", foreground="green")
        self.status_label.pack(pady=10)

        self.log_area = scrolledtext.ScrolledText(root, width=80, height=20, state='disabled', bg="#2d2d2d", fg="white", font=("Courier", 12))
        self.log_area.pack(pady=10)

        self.path_button = ttk.Button(root, text="Seleccionar Carpeta", command=self.select_scan_path)
        self.path_button.pack(pady=5)

        self.scan_button = ttk.Button(root, text="Escanear archivos", command=self.start_file_scan)
        self.scan_button.pack(pady=5)

        self.start_button = ttk.Button(root, text="Iniciar monitoreo", command=self.start_monitoring)
        self.start_button.pack(pady=5)

        self.stop_button = ttk.Button(root, text="Detener monitoreo", command=self.stop_monitoring)
        self.stop_button.pack(pady=5)

    def update_log(self, message):
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.config(state='disabled')
        self.log_area.yview(tk.END)

    def select_scan_path(self):
        self.scan_path = filedialog.askdirectory()
        self.update_log(f"📁 Carpeta seleccionada: {self.scan_path}")

    def start_file_scan(self):
        if self.scan_path:
            threading.Thread(target=self.monitor.scan_files, args=(self.scan_path,), daemon=True).start()
        else:
            self.update_log("⚠️ Por favor, selecciona una carpeta antes de escanear.")

    def start_monitoring(self):
        threading.Thread(target=self.monitor.start_network_monitoring, daemon=True).start()
        threading.Thread(target=self.monitor.monitor_system, daemon=True).start()
        self.update_log("🛡️ Monitoreo iniciado...")

    def stop_monitoring(self):
        self.update_log("⏹️ Monitoreo detenido...")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityApp(root)
    root.mainloop()
