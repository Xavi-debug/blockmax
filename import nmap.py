import logging
from scapy.all import *
from datetime import datetime
import requests
import json
import threading
from collections import defaultdict
import psutil
import yara
import os

class SecurityMonitor:
    def __init__(self):
        self.attack_threshold = 100  # Umbral de paquetes por segundo
        self.connection_count = defaultdict(int)
        self.blocked_ips = set()
        self.logger = self._setup_logger()
        
    def _setup_logger(self):
        logger = logging.getLogger('SecurityMonitor')
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler('security.log')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def analyze_packet(self, packet):
        """Analiza paquetes de red en busca de patrones maliciosos"""
        if IP in packet:
            src_ip = packet[IP].src
            self.connection_count[src_ip] += 1
            
            # Detectar posible DoS
            if self.connection_count[src_ip] > self.attack_threshold:
                self.handle_potential_attack(src_ip)

    def handle_potential_attack(self, ip):
        """Maneja potenciales ataques"""
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            self.logger.warning(f"Posible ataque DoS detectado desde {ip}")
            self.gather_threat_intel(ip)
            self.apply_firewall_rule(ip)

    def gather_threat_intel(self, ip):
        """Recopila información de inteligencia de amenazas usando fuentes abiertas"""
        try:
            # Consulta a AbuseIPDB (requiere API key)
            response = requests.get(
                f'https://api.abuseipdb.com/api/v2/check',
                params={'ipAddress': ip},
                headers={'Key': 'TU_API_KEY'},
            )
            if response.status_code == 200:
                data = response.json()
                self.logger.info(f"Información de amenaza para {ip}: {data}")
        except Exception as e:
            self.logger.error(f"Error al obtener información de amenazas: {e}")

    def apply_firewall_rule(self, ip):
        """Aplica reglas de firewall para bloquear IPs maliciosas"""
        try:
            if os.name == 'posix':  # Para sistemas Linux
                os.system(f'iptables -A INPUT -s {ip} -j DROP')
            elif os.name == 'nt':  # Para sistemas Windows
                os.system(f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}')
            self.logger.info(f"IP {ip} bloqueada en el firewall")
        except Exception as e:
            self.logger.error(f"Error al aplicar regla de firewall: {e}")

    def scan_files(self, path):
        """Escanea archivos en busca de malware usando reglas YARA"""
        try:
            rules = yara.compile('rules.yar')  # Archivo con reglas YARA
            for root, _, files in os.walk(path):
                for file in files:
                    full_path = os.path.join(root, file)
                    matches = rules.match(full_path)
                    if matches:
                        self.logger.warning(f"Malware potencial detectado en {full_path}: {matches}")
        except Exception as e:
            self.logger.error(f"Error en escaneo de archivos: {e}")

    def monitor_system(self):
        """Monitorea recursos del sistema"""
        while True:
            cpu_percent = psutil.cpu_percent()
            memory_percent = psutil.virtual_memory().percent
            if cpu_percent > 90 or memory_percent > 90:
                self.logger.warning(f"Alto uso de recursos - CPU: {cpu_percent}%, Memoria: {memory_percent}%")
            time.sleep(5)

    def start(self):
        """Inicia el sistema de monitorización"""
        # Inicia el monitor de sistema en un hilo separado
        threading.Thread(target=self.monitor_system, daemon=True).start()
        
        # Inicia la captura de paquetes
        try:
            self.logger.info("Iniciando monitorización de red...")
            sniff(prn=self.analyze_packet, store=0)
        except Exception as e:
            self.logger.error(f"Error en la captura de paquetes: {e}")

if __name__ == "__main__":
    monitor = SecurityMonitor()
    monitor.start()
