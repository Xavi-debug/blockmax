import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import logging
from scapy.all import *
import psutil
import yara
import os
import time
from collections import defaultdict

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
            self.gui.update_log(f"Posible ataque DoS detectado desde {ip}")
            self.apply_firewall_rule(ip)

    def apply_firewall_rule(self, ip):
        try:
            if os.name == 'posix':
                os.system(f'iptables -A INPUT -s {ip} -j DROP')
            elif os.name == 'nt':
                os.system(f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}')
            self.logger.info(f"IP {ip} bloqueada en el firewall")
            self.gui.update_log(f"IP {ip} bloqueada en el firewall")
        except Exception as e:
            self.logger.error(f"Error al aplicar regla de firewall: {e}")
            self.gui.update_log(f"Error al aplicar regla de firewall: {e}")

    def scan_files(self, path):
        try:
            for root, _, files in os.walk(path):
                for file in files:
                    full_path = os.path.join(root, file)
                    matches = self.yara_rules.match(full_path)
                    if matches:
                        self.logger.warning(f"Malware potencial detectado en {full_path}: {matches}")
                        self.gui.update_log(f"Malware potencial detectado en {full_path}: {matches}")
        except Exception as e:
            self.logger.error(f"Error en escaneo de archivos: {e}")
            self.gui.update_log(f"Error en escaneo de archivos: {e}")

    def monitor_system(self):
        while True:
            cpu_percent = psutil.cpu_percent()
            memory_percent = psutil.virtual_memory().percent
            if cpu_percent > 90 or memory_percent > 90:
                self.logger.warning(f"Alto uso de recursos - CPU: {cpu_percent}%, Memoria: {memory_percent}%")
                self.gui.update_log(f"Alto uso de recursos - CPU: {cpu_percent}%, Memoria: {memory_percent}%")
            time.sleep(5)

    def start_network_monitoring(self):
        try:
            self.logger.info("Iniciando monitorización de red...")
            self.gui.update_log("Iniciando monitorización de red...")
            sniff(prn=self.analyze_packet, store=0)
        except Exception as e:
            self.logger.error(f"Error en la captura de paquetes: {e}")
            self.gui.update_log(f"Error en la captura de paquetes: {e}")

class SecurityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("BlockMax - Sistema de Defensa")
        self.monitor = SecurityMonitor(self)

        # Panel de estado
        self.status_label = ttk.Label(root, text="Estado: Seguro", font=("Arial", 16))
        self.status_label.pack(pady=10)

        # Área de logs
        self.log_area = scrolledtext.ScrolledText(root, width=80, height=20, state='disabled')
        self.log_area.pack(pady=10)

        # Botones de acción
        self.scan_button = ttk.Button(root, text="Escanear archivos", command=self.start_file_scan)
        self.scan_button.pack(pady=5)

        self.start_button = ttk.Button(root, text="Iniciar monitoreo", command=self.start_monitoring)
        self.start_button.pack(pady=5)

        self.stop_button = ttk.Button(root, text="Detener monitoreo", command=self.stop_monitoring)
        self.stop_button.pack(pady=5)

    def update_log(self, message):
        """Actualiza el área de logs con un nuevo mensaje"""
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.config(state='disabled')
        self.log_area.yview(tk.END)

    def start_file_scan(self):
        """Inicia el escaneo de archivos en un hilo separado"""
        path = "/ruta/a/escaneo"  # Cambia esto por la ruta que desees escanear
        threading.Thread(target=self.monitor.scan_files, args=(path,), daemon=True).start()

    def start_monitoring(self):
        """Inicia el monitoreo de red y sistema"""
        threading.Thread(target=self.monitor.start_network_monitoring, daemon=True).start()
        threading.Thread(target=self.monitor.monitor_system, daemon=True).start()
        self.update_log("Monitoreo iniciado...")

    def stop_monitoring(self):
        """Detiene el monitoreo (esto es un ejemplo, Scapy no tiene un método stop directo)"""
        self.update_log("Monitoreo detenido...")
        # Aquí podrías agregar lógica para detener Scapy si es necesario

if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityApp(root)
    root.mainloop()
