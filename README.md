# Network Traffic Analyzer 🔍

Herramienta de análisis de tráfico de red orientada a Blue Team, 
capaz de detectar amenazas comunes a partir de capturas `.pcap`.

## Capacidades de detección
- 📡 Análisis de protocolos y top IPs por volumen de tráfico
- ⚠️ Detección de escaneo de puertos
- 🔀 Detección de ARP Spoofing
- 🌐 Consulta de reputación de IPs externas vía VirusTotal API
- 📄 Generación automática de informes con timestamp

## Output de ejemplo
![Análisis de tráfico](docs\\screenshots\\output_example.png)

## Tecnologías
Python 3 · Scapy · VirusTotal API · python-dotenv

## Hallazgo real en la captura de prueba
Durante el análisis de la captura de muestra se detectaron:
- **Escaneo de puertos** desde 10.2.28.2 (178 puertos distintos)
- **IP maliciosa** 45.131.214.85 con 11 detecciones en VirusTotal, 
  en comunicación con el host principal 10.2.28.88

## Uso
```bash
# Instalar dependencias
pip install scapy requests python-dotenv

# Configurar API key en archivo .env
VT_API_KEY=tu_api_key

# Ejecutar
cd src
python analyzer.py
```

## Estructura del proyecto
```
NetworkTrafficAnalyzer/
├── src/analyzer.py       # Script principal
├── docs/                 # Informes generados automáticamente
└── resources/samples/    # Capturas .pcap de prueba
```