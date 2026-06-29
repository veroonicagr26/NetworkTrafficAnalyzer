from scapy.all import rdpcap
from collections import Counter

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