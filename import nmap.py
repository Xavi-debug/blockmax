import nmap
import maltego
import shodan
from scapy.all import *

class Hackback:
    def __init__(self):
        self.nmap = nmap.PortScanner()
        self.maltego = maltego.Maltego()
        self.shodan = shodan.Shodan()

    def hackback(self, ip_address):
        # Realiza un escaneo con nmap 
        results = self.nmap.scan(ip_address, '1-1024')
        # Transformaciones con Maltego 
        transformed_results = self.maltego.transform(results)
        # Busca información adicional en Shodan 
        additional_info = self.shodan.search(transformed_results)
        print(f"Información obtenida sobre {ip_address}: {additional_info}")

    def detect_suspicious_activity(self, packet):
        # Analiza el paquete y determina si es sospechoso
        if packet.haslayer(TCP) and packet.flags == 'S':
            return True
        return False

    def on_suspicious_activity_detected(self, ip_address):
        self.hackback(ip_address)