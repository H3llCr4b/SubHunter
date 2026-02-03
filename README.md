# SubHunter

**Ultimate Infrastructure Discovery & Cloud Mapping Tool**

Herramienta profesional de reconocimiento de infraestructura en Python con capacidades avanzadas de descubrimiento de subdominios, IPs públicas y mapeo de infraestructura cloud.

## Características

- **20+ Fuentes Gratuitas** de subdominios (crt.sh, HackerTarget, ThreatCrowd, Wayback, etc.)
- **Descubrimiento de IPs Públicas** incluyendo infraestructura cloud (GCP, AWS, Azure, Cloudflare)
- **Mapeo de Infraestructura Cloud** con detección automática de proveedores
- **Análisis de ASN** para identificar propietarios de rangos IP
- **Resolución DNS masiva** con multi-threading
- **Validación activa** de hosts HTTP/HTTPS
- **Detección de tecnologías** (frameworks, servidores, plataformas)
- **Exportación múltiple** (TXT, JSON, CSV)
- **100% Gratuito** - No requiere API keys

## Instalación

### Dependencias del sistema
```bash
# Debian/Ubuntu
sudo apt update
sudo apt install python3 python3-pip

# CentOS/RHEL
sudo yum install python3 python3-pip
```

### Instalación de módulos Python
```bash
pip3 install -r requirements.txt
```

O manualmente:
```bash
pip3 install dnspython requests aiohttp
```

## Uso Básico

### Escaneo simple
```bash
python3 subhunter.py -d example.com
```

### Escaneo con más threads (más rápido)
```bash
python3 subhunter.py -d example.com -t 100
```

### Modo verbose (ver progreso en tiempo real)
```bash
python3 subhunter.py -d example.com -t 100 -v
```

### Especificar directorio de salida
```bash
python3 subhunter.py -d example.com -o /tmp/mi_scan
```

### Saltar validación activa (más rápido)
```bash
python3 subhunter.py -d example.com --skip-active
```

### Saltar análisis cloud (más rápido)
```bash
python3 subhunter.py -d example.com --skip-cloud
```

### Escaneo completo con todas las opciones
```bash
python3 subhunter.py -d example.com -t 200 -T 3 -v -o ./resultados
```

## Parámetros

```
-d, --domain         Dominio objetivo (REQUERIDO)
-o, --output         Directorio de salida (opcional)
-t, --threads        Número de threads (default: 50)
-T, --timeout        Timeout en segundos (default: 5)
-v, --verbose        Modo verbose
--skip-active        Saltar validación activa de hosts
--skip-cloud         Saltar análisis de infraestructura cloud
--export-format      Formato de exportación: csv, json o both (default: both)
--version            Mostrar versión
-h, --help           Mostrar ayuda
```

##  Archivos Generados

El script genera los siguientes archivos en el directorio de salida:

### Archivos principales
- `all_subdomains.txt` - Lista completa de subdominios encontrados
- `resolved.txt` - Subdominios con sus IPs (formato: subdominio|ip)
- `ips_unique.txt` - Lista de IPs únicas
- `http_alive.txt` - URLs que responden HTTP/HTTPS
- `REPORT.txt` - Reporte completo en texto plano

### Archivos de infraestructura cloud
- `cloud_infrastructure.json` - IPs cloud con metadata completa
- `cloud_infrastructure.csv` - IPs cloud en formato CSV
- `asn_information.json` - Información de ASN de todas las IPs

### Archivos de análisis
- `technologies.json` - Tecnologías detectadas por host
- `full_scan_data.json` - Datos completos del escaneo en JSON
- `complete_export.csv` - **EXPORTACIÓN COMPLETA EN CSV** (TODA la info)
- `complete_export.json` - **EXPORTACIÓN COMPLETA EN JSON** (TODA la info)

### Archivos para otras herramientas
- `targets_for_nmap.txt` - Lista de IPs para escanear con nmap

## 🔍 Fuentes Consultadas

1. **crt.sh** - Certificate Transparency Logs
2. **HackerTarget** - Subdomain lookup API
3. **ThreatCrowd** - Threat intelligence database
4. **Wayback Machine** - Historical subdomain data
5. **VirusTotal** - Domain intelligence
6. **AlienVault OTX** - Open Threat Exchange
7. **URLScan.io** - URL scanner database
8. **CertSpotter** - Certificate monitoring
9. **RapidDNS** - DNS database
10. **Anubis DB** - Subdomain database
11. **CommonCrawl** - Web crawl data
12. **DNS Brute Force** - Common subdomain wordlist

## Detección de Cloud Providers

La herramienta detecta automáticamente si las IPs pertenecen a:

- **Google Cloud Platform (GCP)**
  - ASN: AS15169, AS139070, AS19527
  - Rangos IP oficiales de gstatic.com

- **Amazon Web Services (AWS)**
  - ASN: AS16509, AS14618
  - Rangos IP oficiales de AWS

- **Microsoft Azure**
  - ASN: AS8075, AS8068
  - Detección por headers y ASN

- **Cloudflare**
  - ASN: AS13335
  - Rangos IP públicos de Cloudflare

## Ejemplos de Uso

### Caso 1: Reconocimiento rápido
```bash
# Obtener subdominios sin validación activa (más rápido)
python3 subhunter.py -d target.com --skip-active --skip-cloud
```

### Caso 2: Mapeo completo de infraestructura
```bash
# Escaneo completo con análisis cloud
python3 subhunter.py -d target.com -t 200 -v
```

### Caso 3: Exportación completa en CSV
```bash
# Generar solo CSV con toda la información
python3 subhunter.py -d target.com -t 150 --export-format csv
```

### Caso 4: Exportación completa en JSON
```bash
# Generar solo JSON con toda la información
python3 subhunter.py -d target.com -t 150 --export-format json
```

### Caso 5: Enfoque en cloud
```bash
# Solo análisis de infraestructura cloud
python3 subhunter.py -d target.com -t 100 --skip-active
```

### Caso 6: Máxima velocidad
```bash
# Escaneo ultra-rápido (sin validación activa ni cloud)
python3 subhunter.py -d target.com -t 300 -T 2 --skip-active --skip-cloud
```

## Exportación Completa

SubHunter genera automáticamente archivos con **TODA** la información recolectada:

### complete_export.csv
Contiene una fila por cada subdomain/IP con las siguientes columnas:
- **Subdomain** - Nombre del subdominio
- **IP** - Dirección IP
- **HTTP URL** - URL HTTP (si está activo)
- **HTTPS URL** - URL HTTPS (si está activo)
- **Is Alive** - Si responde HTTP/HTTPS (Yes/No)
- **Server** - Servidor web detectado
- **Powered By** - Tecnología powered-by
- **Framework** - Framework detectado
- **Cloud Provider** - Proveedor cloud (GCP/AWS/Azure/Cloudflare)
- **Cloud Details** - Detalles del cloud (ASN, rango, etc.)
- **ASN** - Número ASN
- **ASN Organization** - Organización propietaria del ASN
- **ASN Country** - País del ASN

### complete_export.json
Mismo contenido en formato JSON con metadata adicional:
```json
{
  "metadata": {
    "domain": "example.com",
    "scan_date": "2025-12-04T...",
    "total_records": 150,
    "export_format": "complete"
  },
  "data": [...]
}
```

**Ejemplo de uso:**
```bash
# Generar ambos formatos (default)
python3 subhunter.py -d example.com -t 150 -v

# Solo CSV
python3 subhunter.py -d example.com --export-format csv

# Solo JSON
python3 subhunter.py -d example.com --export-format json
```

## 📈 Fases del Escaneo

1. **FASE 1: DESCUBRIMIENTO DE SUBDOMINIOS**
   - Consulta a 20+ fuentes gratuitas
   - Consolidación y deduplicación
   - DNS brute force con wordlist común

2. **FASE 2: RESOLUCIÓN DNS**
   - Resolución A y AAAA records
   - Multi-threading para velocidad
   - Extracción de IPs únicas

3. **FASE 3: ANÁLISIS DE INFRAESTRUCTURA CLOUD**
   - Descarga de rangos IP de proveedores
   - Matching de IPs con rangos cloud
   - Lookup de ASN para IPs no identificadas
   - Detección de proveedor por ASN

4. **FASE 4: VALIDACIÓN ACTIVA**
   - Prueba HTTP/HTTPS en subdominios
   - Detección de códigos de estado
   - Identificación de tecnologías
   - Análisis de headers

5. **FASE 5: GENERACIÓN DE REPORTES**
   - Múltiples formatos de salida
   - Estadísticas detalladas
   - Archivos listos para otras herramientas

## Consideraciones de Seguridad

- Solo usar en dominios autorizados
- Respetar términos de servicio de las APIs
- No abusar de las consultas (rate limiting)
- Mantener logs para auditoría

## Contribuciones

Este es un proyecto educativo para la comunidad.

##  Autor

H3llCr4b

---

**SubHunter** - Ultimate Infrastructure Discovery & Cloud Mapping Tool
