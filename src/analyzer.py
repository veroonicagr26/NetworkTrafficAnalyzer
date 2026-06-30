from scapy.all import rdpcap
from collections import Counter
import requests
from dotenv import load_dotenv
import os
import datetime

load_dotenv("..\\.env")
VT_API_KEY = os.getenv("VT_API_KEY")

# Cargamos la captura
packets = rdpcap("..\\resources\\samples\\2026-02-28-traffic-analysis-exercise.pcap")

print(f"Total de paquetes capturados: {len(packets)}\n")

# Contamos protocolos
protocols = []
src_ips = []
dst_ips = []

for pkt in packets:
    # Protocolo de capa de transporte
    if pkt.haslayer("TCP"):
        protocols.append("TCP")
    elif pkt.haslayer("UDP"):
        protocols.append("UDP")
    elif pkt.haslayer("ARP"):
        protocols.append("ARP")
    else:
        protocols.append("Otro")

    # IPs origen y destino
    if pkt.haslayer("IP"):
        src_ips.append(pkt["IP"].src)
        dst_ips.append(pkt["IP"].dst)

# Resultados
print("=== PROTOCOLOS MÁS FRECUENTES ===")
for proto, count in Counter(protocols).most_common():
    print(f"  {proto}: {count} paquetes")

print("\n=== TOP 5 IPs ORIGEN ===")
for ip, count in Counter(src_ips).most_common(5):
    print(f"  {ip}: {count} paquetes")

print("\n=== TOP 5 IPs DESTINO ===")
for ip, count in Counter(dst_ips).most_common(5):
    print(f"  {ip}: {count} paquetes")


print("\n=== DETECCIÓN DE POSIBLE ESCANEO DE PUERTOS ===")

# Registramos cuántos puertos distintos contacta cada IP origen
from collections import defaultdict

port_scan_tracker = defaultdict(set)

for pkt in packets:
    if pkt.haslayer("TCP") and pkt.haslayer("IP"):
        src = pkt["IP"].src
        dst_port = pkt["TCP"].dport
        port_scan_tracker[src].add(dst_port)

# Umbral: si una IP contacta más de 20 puertos distintos, es sospechoso
UMBRAL = 20
alertas = {ip: ports for ip, ports in port_scan_tracker.items() if len(ports) > UMBRAL}

if alertas:
    for ip, ports in sorted(alertas.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"  ⚠️  {ip} contactó {len(ports)} puertos distintos — posible escaneo")
else:
    print("  ✅ No se detectaron patrones de escaneo de puertos")

print("\n=== DETECCIÓN DE ARP SPOOFING ===")

# Registramos qué MAC responde por cada IP
arp_table = defaultdict(set)

for pkt in packets:
    if pkt.haslayer("ARP") and pkt["ARP"].op == 2:  # op=2 es ARP reply
        ip = pkt["ARP"].psrc
        mac = pkt["ARP"].hwsrc
        arp_table[ip].add(mac)

# Si una IP tiene más de una MAC asociada, es sospechoso
alertas_arp = {ip: macs for ip, macs in arp_table.items() if len(macs) > 1}

if alertas_arp:
    for ip, macs in alertas_arp.items():
        print(f"  ⚠️  {ip} responde con múltiples MACs — posible ARP Spoofing:")
        for mac in macs:
            print(f"       → {mac}")
else:
    print("  ✅ No se detectaron anomalías ARP")




print("\n=== REPUTACIÓN DE IPs EXTERNAS EN VIRUSTOTAL ===")

# Filtramos solo IPs externas (no privadas)
def es_ip_privada(ip):
    return (ip.startswith("10.") or 
            ip.startswith("192.168.") or 
            ip.startswith("172.") or
            ip == "255.255.255.255")

ips_externas = [ip for ip in Counter(src_ips).most_common(10) 
                if not es_ip_privada(ip[0])]

for ip, count in ips_externas[:5]:  # máximo 5 para no agotar el límite gratuito
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        
        if malicious > 0 or suspicious > 0:
            print(f"  ⚠️  {ip} ({count} paquetes) → {malicious} detecciones maliciosas, {suspicious} sospechosas")
        else:
            print(f"  ✅ {ip} ({count} paquetes) → sin detecciones")
    else:
        print(f"  ❌ {ip} → error consultando VirusTotal ({response.status_code})")



print("\n=== GENERANDO INFORME ===")



timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
nombre_informe = f"..\\docs\\informe_{timestamp}.txt"

with open(nombre_informe, "w", encoding="utf-8") as f:
    f.write("=" * 50 + "\n")
    f.write("INFORME DE ANÁLISIS DE TRÁFICO DE RED\n")
    f.write(f"Fecha: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
    f.write("=" * 50 + "\n\n")

    f.write(f"Total de paquetes analizados: {len(packets)}\n\n")

    f.write("HALLAZGOS DETECTADOS:\n")
    f.write("-" * 30 + "\n")

    # Escaneo de puertos
    if alertas:
        for ip, ports in alertas.items():
            f.write(f"[ALERTA] Posible escaneo de puertos — {ip} contactó {len(ports)} puertos distintos\n")

    # ARP Spoofing
    if alertas_arp:
        for ip, macs in alertas_arp.items():
            f.write(f"[ALERTA] Posible ARP Spoofing — {ip} con múltiples MACs: {', '.join(macs)}\n")
    else:
        f.write("[OK] Sin anomalías ARP detectadas\n")

    # IPs maliciosas
    f.write("\nREPUTACIÓN DE IPs EXTERNAS:\n")
    f.write("-" * 30 + "\n")
    for ip, count in ips_externas[:5]:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            estado = "⚠️  MALICIOSA" if malicious > 0 else "✅ Limpia"
            f.write(f"{estado} — {ip} ({count} paquetes) | Maliciosas: {malicious} | Sospechosas: {suspicious}\n")

print(f"  ✅ Informe guardado en: {nombre_informe}")