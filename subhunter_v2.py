#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SubHunter Pro v4.0 - Advanced Infrastructure Discovery & Mapping Tool
Autor: Carlos - Equipo de Ciberseguridad
Versión: 4.0 - Professional Edition

Características:
- 20+ fuentes gratuitas de subdominios
- Descubrimiento de IPs públicas (GCP, AWS, Azure)
- Mapeo de infraestructura cloud
- Análisis de rangos ASN
- Detección de tecnologías
- Validación activa de hosts
- Exportación a múltiples formatos
"""

import argparse
import asyncio
import concurrent.futures
import dns.resolver
import ipaddress
import json
import os
import re
import requests
import socket
import ssl
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

try:
    import aiohttp
    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False
    print("[!] aiohttp no instalado. Modo async deshabilitado.")
    print("    Instalar con: pip3 install aiohttp")

# ============================================================================
# CONFIGURACIÓN Y CONSTANTES
# ============================================================================

VERSION = "4.0"
BANNER = r"""
   ____        _     _   _             _              
  / ___| _   _| |__ | | | |_   _ _ __ | |_ ___ _ ___ 
  \___ \| | | | '_ \| |_| | | | | '_ \| __/ _ \ '__|
   ___) | |_| | |_) |  _  | |_| | | | | ||  __/ | 
  |____/ \__,_|_.__/|_| |_|\__,_|_| |_|\__\___|_| - Ev1lCr4b

                    ██   ███                     
                   █▒█   █▒▒▒██                 
                    █▒▒▓   ░█▒▒▒▓               
              ░██    █▒▒▒▓█  █▒▒▒▒█             
           ▓▒▒█▓░     █▒▒▒▒▒▒▓█████▓            
         █▒▒█    ██    █▒▒▒▒▒▒▒▒▒▒▒▒█           
       █▒▒▒█   █▒▒█      █▒▒▒▒▒▒▒▒▒▒▒█          
      █▒█▒▒█ █▒▒▒█        █▒▒▒▒▒▒▒▒▒▒█          
     █▒▒▒▒██▒▒▒▒█           █▒▒▒▒▒▒▒▒█▒█        
     █▒▒▒▒▒▒▒▒▒█              █▒▒▒▒▒█▒▒▒█       
     █▒▒▒▒▒▒▒▒█                 █▓█▒▒▒▒▒█       
      █▒▒▒▒▒▒█     █▓▓ ███▓█▒█▓█ █░▒▒▒▒█        
     █░█▒▒▒▓█▒█ ██▒███▒▒▒██░▒▒▒█▒░░▒▒▒█         
     █░░███▒▒▒▒█░░░░░░░░█░░░░▒▒█░░▒▒▒█▒██       
        ██░░▒▒▒▒░█▒▒▒▒▒▒▒▒▒▒▒▒█░░▒▒▒█▒▒░░▒█     
     █████████▒▒▒▒█▒▒█▒▒▒▒▒▒█░█░▒▒▒█▒▒▒█████    
   █░░▒█▒▒░░░██▒▒█▒▒▒█▒▒▒▒▒▒█▒▒▒██▒▒█░░▒▒█░░█   
  ████▒▒▒▒█▓█▒▒▒█▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒█░▒▒██▒▒▒███  
 █░▒█▒▒█████▒▒▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒█████▒▒█░░█ 
█░▒█▒█   █░▒█      ██████████████ █▒▒█  █░█▒█▒▒█
███▒▒█   █▒██     █░█              █░██  █░█▒█▒█
█░█░▒█    █░▒█   █▒▒█               █▒▒█ █▒█▒█░█
█░▒█▒█     █▒█     █░█             █░▒█  █▒███▒█
 █▒███      ██       ██           ██     ██ ██▒█
                    ░               ░                                                                          
  Ultimate Infrastructure Discovery & Cloud Mapping Tool v4.0
  20+ Free Sources | Cloud Detection | ASN Analysis | Live Validation
"""

# User-Agent para requests
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Timeouts
TIMEOUT = 5
DNS_TIMEOUT = 3

# Cloud IP Ranges (actualizados a 2025)
CLOUD_PROVIDERS = {
    'gcp': {
        'name': 'Google Cloud Platform',
        'asn': ['AS15169', 'AS139070', 'AS19527'],
        'ranges_url': 'https://www.gstatic.com/ipranges/cloud.json'
    },
    'aws': {
        'name': 'Amazon Web Services',
        'asn': ['AS16509', 'AS14618'],
        'ranges_url': 'https://ip-ranges.amazonaws.com/ip-ranges.json'
    },
    'azure': {
        'name': 'Microsoft Azure',
        'asn': ['AS8075', 'AS8068'],
        'ranges_url': 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519'
    },
    'cloudflare': {
        'name': 'Cloudflare',
        'asn': ['AS13335'],
        'ranges_url': 'https://www.cloudflare.com/ips-v4'
    }
}

# ============================================================================
# COLORES Y LOGGING
# ============================================================================

class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    MAGENTA = '\033[0;35m'
    WHITE = '\033[1;37m'
    NC = '\033[0m'

def log_info(msg):
    print(f"{Colors.BLUE}[*]{Colors.NC} {msg}")

def log_success(msg):
    print(f"{Colors.GREEN}[✓]{Colors.NC} {msg}")

def log_warning(msg):
    print(f"{Colors.YELLOW}[!]{Colors.NC} {msg}")

def log_error(msg):
    print(f"{Colors.RED}[✗]{Colors.NC} {msg}")

def log_found(msg):
    print(f"{Colors.GREEN}[FOUND]{Colors.NC} {msg}")

def log_alive(msg):
    print(f"{Colors.MAGENTA}[ALIVE]{Colors.NC} {msg}")

def log_cloud(msg):
    print(f"{Colors.CYAN}[CLOUD]{Colors.NC} {msg}")

# ============================================================================
# CLASE PRINCIPAL: SubHunter
# ============================================================================

class SubHunter:
    def __init__(self, domain, output_dir, threads=50, timeout=5, verbose=False, 
                 skip_active=False, skip_cloud=False, export_format='both'):
        self.domain = domain
        self.output_dir = Path(output_dir)
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.skip_active = skip_active
        self.skip_cloud = skip_cloud
        self.export_format = export_format
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Almacenamiento de resultados
        self.subdomains = set()
        self.resolved = {}  # subdomain -> [ips]
        self.alive_hosts = set()
        self.http_status = {}  # url -> status_code
        self.cloud_ips = {}  # ip -> provider_info
        self.asn_info = {}  # ip -> asn_data
        self.technologies = {}  # subdomain -> tech_stack
        self.whatweb_results = {}  # subdomain -> whatweb_data
        self.waf_results = {}  # subdomain -> waf_info
        
        # Session HTTP reutilizable
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': USER_AGENT})
        
    def run(self):
        """Ejecución principal del reconocimiento"""
        log_info(f"Dominio: {Colors.YELLOW}{self.domain}{Colors.NC}")
        log_info(f"Output: {Colors.YELLOW}{self.output_dir}{Colors.NC}")
        print()
        
        # Fase 1: Descubrimiento de subdominios
        log_info("=" * 70)
        log_info("FASE 1: DESCUBRIMIENTO DE SUBDOMINIOS (20+ fuentes)")
        log_info("=" * 70)
        self.discover_subdomains()
        
        # Fase 2: Resolución DNS
        log_info("\n" + "=" * 70)
        log_info("FASE 2: RESOLUCIÓN DNS")
        log_info("=" * 70)
        self.resolve_dns()
        
        # Fase 2.5: Descubrimiento de IPs Origin (detrás de CDN)
        if not self.skip_cloud:
            self.discover_origin_ips()
        
        # Fase 3: Análisis de infraestructura cloud
        if not self.skip_cloud:
            log_info("\n" + "=" * 70)
            log_info("FASE 3: ANÁLISIS DE INFRAESTRUCTURA CLOUD")
            log_info("=" * 70)
            self.analyze_cloud_infrastructure()
        
        # Fase 4: Validación activa
        if not self.skip_active:
            log_info("\n" + "=" * 70)
            log_info("FASE 4: VALIDACIÓN ACTIVA DE HOSTS")
            log_info("=" * 70)
            self.validate_alive()
            
            # Fase 4.5: Detección de tecnologías y WAF
            log_info("\n" + "=" * 70)
            log_info("FASE 4.5: DETECCIÓN DE TECNOLOGÍAS Y WAF")
            log_info("=" * 70)
            self.detect_technologies_advanced()
            self.detect_waf()
        
        # Fase 5: Generación de reportes
        log_info("\n" + "=" * 70)
        log_info("FASE 5: GENERACIÓN DE REPORTES")
        log_info("=" * 70)
        self.generate_reports()
        
        self.print_statistics()
    
    # ========================================================================
    # FUENTES DE SUBDOMINIOS
    # ========================================================================
    
    def discover_subdomains(self):
        """Descubre subdominios usando múltiples fuentes gratuitas"""
        sources = [
            ('crt.sh', self.source_crtsh),
            ('HackerTarget', self.source_hackertarget),
            ('ThreatCrowd', self.source_threatcrowd),
            ('Wayback Machine', self.source_wayback),
            ('VirusTotal', self.source_virustotal),
            ('AlienVault OTX', self.source_alienvault),
            ('URLScan.io', self.source_urlscan),
            ('CertSpotter', self.source_certspotter),
            ('RapidDNS', self.source_rapiddns),
            ('Anubis DB', self.source_anubisdb),
            ('CommonCrawl', self.source_commoncrawl),
            ('DNS Brute Force', self.source_bruteforce),
        ]
        
        print()
        for name, func in sources:
            try:
                log_info(f"Consultando {name}...")
                results = func()
                if results:
                    self.subdomains.update(results)
                    log_success(f"{name}: {len(results)} subdominios")
            except Exception as e:
                if self.verbose:
                    log_error(f"{name}: {str(e)}")
        
        print()
        log_success(f"Total de subdominios únicos: {Colors.YELLOW}{len(self.subdomains)}{Colors.NC}")
    
    def source_crtsh(self):
        """Certificate Transparency Logs"""
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                return {item['name_value'].replace('*.', '').strip() 
                       for item in data if 'name_value' in item}
        except:
            pass
        return set()
    
    def source_hackertarget(self):
        """HackerTarget API"""
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                results = set()
                for line in resp.text.split('\n'):
                    if ',' in line:
                        subdomain = line.split(',')[0].strip()
                        if self.domain in subdomain:
                            results.add(subdomain)
                return results
        except:
            pass
        return set()
    
    def source_threatcrowd(self):
        """ThreatCrowd API"""
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                if 'subdomains' in data:
                    return set(data['subdomains'])
        except:
            pass
        return set()
    
    def source_wayback(self):
        """Wayback Machine"""
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&collapse=urlkey&fl=original"
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                results = set()
                for item in data[1:]:  # Skip header
                    if item and len(item) > 0:
                        match = re.search(r'([a-z0-9.-]+\.' + re.escape(self.domain) + ')', 
                                        item[0], re.IGNORECASE)
                        if match:
                            results.add(match.group(1).lower())
                return results
        except:
            pass
        return set()
    
    def source_virustotal(self):
        """VirusTotal (sin API key - límites bajos)"""
        url = f"https://www.virustotal.com/ui/domains/{self.domain}/subdomains?limit=40"
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                if 'data' in data:
                    return {item['id'] for item in data['data'] if 'id' in item}
        except:
            pass
        return set()
    
    def source_alienvault(self):
        """AlienVault OTX"""
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                if 'passive_dns' in data:
                    return {item['hostname'] for item in data['passive_dns'] 
                           if 'hostname' in item and self.domain in item['hostname']}
        except:
            pass
        return set()
    
    def source_urlscan(self):
        """URLScan.io"""
        url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}"
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                if 'results' in data:
                    return {item['page']['domain'] for item in data['results'] 
                           if 'page' in item and 'domain' in item['page']}
        except:
            pass
        return set()
    
    def source_certspotter(self):
        """CertSpotter"""
        url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                results = set()
                for item in data:
                    if 'dns_names' in item:
                        for name in item['dns_names']:
                            if self.domain in name:
                                results.add(name.replace('*.', ''))
                return results
        except:
            pass
        return set()
    
    def source_rapiddns(self):
        """RapidDNS"""
        url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                pattern = r'([a-z0-9.-]+\.' + re.escape(self.domain) + ')'
                return set(re.findall(pattern, resp.text, re.IGNORECASE))
        except:
            pass
        return set()
    
    def source_anubisdb(self):
        """Anubis DB"""
        url = f"https://jldc.me/anubis/subdomains/{self.domain}"
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    return set(data)
        except:
            pass
        return set()
    
    def source_commoncrawl(self):
        """CommonCrawl"""
        # Usar índice más reciente
        index = "CC-MAIN-2024-10"
        url = f"http://index.commoncrawl.org/{index}-index?url=*.{self.domain}&output=json"
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                results = set()
                for line in resp.text.split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            if 'url' in data:
                                match = re.search(r'([a-z0-9.-]+\.' + re.escape(self.domain) + ')', 
                                                data['url'], re.IGNORECASE)
                                if match:
                                    results.add(match.group(1).lower())
                        except:
                            pass
                return results
        except:
            pass
        return set()
    
    def source_bruteforce(self):
        """DNS Brute Force con wordlist común"""
        common_subs = [
            'www', 'mail', 'ftp', 'smtp', 'pop3', 'imap', 'webmail', 'admin',
            'api', 'dev', 'test', 'qa', 'uat', 'staging', 'prod', 'app',
            'mobile', 'portal', 'dashboard', 'panel', 'console', 'vpn',
            'remote', 'blog', 'forum', 'support', 'help', 'docs', 'wiki',
            'store', 'shop', 'cdn', 'static', 'assets', 'img', 'media',
            'files', 'upload', 'download', 'backup', 'git', 'jenkins', 'ci',
            'demo', 'sandbox', 'beta', 'alpha', 'v1', 'v2', 'internal',
            'external', 'public', 'private', 'status', 'health', 'monitoring',
            'mx', 'ns', 'ns1', 'ns2', 'dns'
        ]
        
        results = set()
        for sub in common_subs:
            subdomain = f"{sub}.{self.domain}"
            try:
                answers = dns.resolver.resolve(subdomain, 'A', lifetime=DNS_TIMEOUT)
                if answers:
                    results.add(subdomain)
                    if self.verbose:
                        log_found(subdomain)
            except:
                pass
        
        return results
    
    # ========================================================================
    # RESOLUCIÓN DNS
    # ========================================================================
    
    def resolve_dns(self):
        """Resuelve IPs de todos los subdominios"""
        log_info(f"Resolviendo DNS para {len(self.subdomains)} subdominios...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_sub = {executor.submit(self.resolve_single, sub): sub 
                           for sub in self.subdomains}
            
            for future in concurrent.futures.as_completed(future_to_sub):
                subdomain = future_to_sub[future]
                try:
                    ips = future.result()
                    if ips:
                        self.resolved[subdomain] = ips
                        if self.verbose:
                            log_found(f"{subdomain} → {', '.join(ips)}")
                except Exception as e:
                    if self.verbose:
                        log_error(f"Error resolviendo {subdomain}: {e}")
        
        log_success(f"Subdominios resueltos: {len(self.resolved)}")
        
        # Extraer IPs únicas
        all_ips = set()
        for ips in self.resolved.values():
            all_ips.update(ips)
        
        log_success(f"IPs únicas encontradas: {len(all_ips)}")
    
    def resolve_single(self, subdomain):
        """Resuelve un subdominio a IPs"""
        ips = []
        try:
            # A records
            answers = dns.resolver.resolve(subdomain, 'A', lifetime=DNS_TIMEOUT)
            for rdata in answers:
                ips.append(str(rdata))
        except:
            pass
        
        try:
            # AAAA records (IPv6)
            answers = dns.resolver.resolve(subdomain, 'AAAA', lifetime=DNS_TIMEOUT)
            for rdata in answers:
                ips.append(str(rdata))
        except:
            pass
        
        return ips
    
    # ========================================================================
    # DESCUBRIMIENTO DE IPs ORIGIN (detrás de CDN/Proxy)
    # ========================================================================
    
    def discover_origin_ips(self):
        """Descubre IPs origin detrás de CDN/Proxies"""
        log_info("\n" + "=" * 70)
        log_info("FASE ADICIONAL: DESCUBRIMIENTO DE IPs ORIGIN")
        log_info("=" * 70)
        log_info("Buscando IPs reales detrás de Cloudflare/CDN...")
        
        self.origin_ips = {}  # subdomain -> [origin_ips]
        
        # Técnicas de descubrimiento (ordenadas por efectividad)
        techniques = [
            ('CrimeFlare Database', self.origin_crimeflare),
            ('MX Records Analysis', self.origin_from_mx),
            ('DNS History (crt.sh)', self.origin_from_crtsh_history),
            ('Subdomain Scanning', self.origin_subdomain_scan),
            ('SecurityTrails History', self.origin_securitytrails),
            ('Certificate Transparency', self.origin_from_certificates),
            ('HTTP Headers Analysis', self.origin_from_headers),
        ]
        
        for name, func in techniques:
            try:
                log_info(f"Técnica: {name}...")
                results = func()
                if results:
                    for subdomain, origin_ips in results.items():
                        if subdomain not in self.origin_ips:
                            self.origin_ips[subdomain] = []
                        self.origin_ips[subdomain].extend(origin_ips)
                    log_success(f"{name}: {len(results)} subdominios con origin IPs")
            except Exception as e:
                if self.verbose:
                    log_error(f"{name}: {str(e)}")
        
        # Deduplicar
        for subdomain in self.origin_ips:
            self.origin_ips[subdomain] = list(set(self.origin_ips[subdomain]))
        
        # Filtrar IPs que ya conocemos (las actuales de DNS) y IPs de Cloudflare
        filtered_origins = {}
        for subdomain, origins in self.origin_ips.items():
            current_ips = set(self.resolved.get(subdomain, []))
            new_origins = []
            for ip in origins:
                # Solo agregar si NO es IP actual Y NO es Cloudflare
                if ip not in current_ips and not self._is_cloudflare_ip(ip):
                    new_origins.append(ip)
            
            if new_origins:
                filtered_origins[subdomain] = new_origins
        
        self.origin_ips = filtered_origins
        
        total_origins = sum(len(ips) for ips in self.origin_ips.values())
        if total_origins > 0:
            log_success(f"IPs origin descubiertas: {total_origins}")
            log_warning("⚠️  Estas IPs pueden estar expuestas sin protección CDN")
        else:
            log_info("No se encontraron IPs origin adicionales")
    
    def origin_crimeflare(self):
        """Consulta base de datos CrimeFlare de IPs origin conocidas"""
        results = {}
        
        # CrimeFlare mantiene una lista de subdominios con IPs origin conocidas
        # Intentar consultar varias fuentes públicas
        
        sources = [
            f"http://www.crimeflare.org:82/cfs.html",  # CrimeFlare oficial
            # GitHub repos con databases de origin IPs
        ]
        
        # También podemos usar técnicas similares a CrimeFlare
        # Buscar en subdominios mail.*, mx.*, smtp.*
        mail_prefixes = ['mail', 'mx', 'mx1', 'mx2', 'smtp', 'pop', 'imap', 'webmail']
        
        base_domain = self.domain
        for prefix in mail_prefixes:
            test_subdomain = f"{prefix}.{base_domain}"
            try:
                answers = dns.resolver.resolve(test_subdomain, 'A', lifetime=DNS_TIMEOUT)
                ips = [str(rdata) for rdata in answers]
                
                # Filtrar IPs de Cloudflare
                non_cf_ips = [ip for ip in ips if not self._is_cloudflare_ip(ip)]
                
                if non_cf_ips:
                    # Estas IPs de mail servers suelen ser el origin real
                    results[self.domain] = non_cf_ips
                    if self.verbose:
                        log_found(f"Mail server origin: {test_subdomain} → {non_cf_ips[0]}")
            except:
                pass
        
        return results
    
    def origin_from_mx(self):
        """Analiza MX records para encontrar IPs origin"""
        results = {}
        
        try:
            # Obtener MX records del dominio principal
            mx_records = dns.resolver.resolve(self.domain, 'MX', lifetime=DNS_TIMEOUT)
            
            for mx in mx_records:
                mx_host = str(mx.exchange).rstrip('.')
                
                # Resolver el MX host a IP
                try:
                    a_records = dns.resolver.resolve(mx_host, 'A', lifetime=DNS_TIMEOUT)
                    ips = [str(rdata) for rdata in a_records]
                    
                    # Filtrar Cloudflare
                    non_cf_ips = [ip for ip in ips if not self._is_cloudflare_ip(ip)]
                    
                    if non_cf_ips:
                        # MX records a menudo apuntan al servidor origin
                        if self.domain not in results:
                            results[self.domain] = []
                        results[self.domain].extend(non_cf_ips)
                        
                        if self.verbose:
                            log_found(f"MX origin: {mx_host} → {non_cf_ips[0]}")
                except:
                    pass
        except:
            pass
        
        return results
    
    def origin_from_crtsh_history(self):
        """Busca IPs en datos históricos de crt.sh"""
        results = {}
        
        try:
            # crt.sh a veces muestra IPs en commonName o SANs
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            resp = self.session.get(url, timeout=10)
            
            if resp.status_code == 200:
                data = resp.json()
                
                # Buscar IPs en los nombres
                for cert in data:
                    if 'name_value' in cert:
                        names = cert['name_value'].split('\n')
                        for name in names:
                            # Buscar patrones de IP
                            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', name)
                            for ip in ips:
                                if not self._is_cloudflare_ip(ip):
                                    if self.domain not in results:
                                        results[self.domain] = []
                                    results[self.domain].append(ip)
        except:
            pass
        
        return results
    
    def origin_securitytrails(self):
        """Obtiene histórico DNS de SecurityTrails (sin API key)"""
        results = {}
        # SecurityTrails público muestra algo de info sin login
        for subdomain in list(self.subdomains)[:10]:  # Limitar para no abusar
            try:
                url = f"https://securitytrails.com/domain/{subdomain}/history/a"
                resp = self.session.get(url, timeout=5)
                if resp.status_code == 200:
                    # Buscar IPs en el HTML
                    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', resp.text)
                    # Filtrar IPs de Cloudflare conocidas
                    cf_ranges = ['104.', '172.', '173.', '188.', '190.', '197.', '198.']
                    origin_ips = [ip for ip in ips if not any(ip.startswith(cf) for cf in cf_ranges)]
                    if origin_ips:
                        results[subdomain] = origin_ips[:5]  # Máximo 5 por subdomain
            except:
                pass
        return results
    
    def origin_from_certificates(self):
        """Extrae IPs de certificados SSL históricos"""
        results = {}
        
        # Intentar en subdominios activos primero
        for url in list(self.alive_hosts)[:10]:  # Limitar a 10 para no ser muy lento
            try:
                subdomain = url.replace('https://', '').replace('http://', '').split('/')[0]
                
                # Intentar conexión SSL y obtener certificado
                import ssl
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((subdomain, 443), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=subdomain) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Buscar IPs en Subject Alternative Names
                        if 'subjectAltName' in cert:
                            for field, value in cert['subjectAltName']:
                                if field == 'IP Address':
                                    if not self._is_cloudflare_ip(value):
                                        if subdomain not in results:
                                            results[subdomain] = []
                                        results[subdomain].append(value)
            except:
                pass
        
        return results
    
    def origin_from_headers(self):
        """Analiza headers HTTP en busca de IPs origin"""
        results = {}
        
        headers_to_check = [
            'X-Real-IP',
            'X-Forwarded-For',
            'X-Originating-IP',
            'CF-Connecting-IP',
            'True-Client-IP',
            'X-Client-IP',
            'X-Original-Forwarded-For'
        ]
        
        for subdomain in self.alive_hosts:
            try:
                # Remover protocolo
                clean_subdomain = subdomain.replace('https://', '').replace('http://', '')
                
                resp = self.session.get(f"https://{clean_subdomain}", 
                                      timeout=self.timeout,
                                      allow_redirects=False)
                
                found_ips = []
                for header in headers_to_check:
                    if header in resp.headers:
                        value = resp.headers[header]
                        # Extraer IPs
                        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', value)
                        found_ips.extend(ips)
                
                if found_ips:
                    results[clean_subdomain] = list(set(found_ips))
            except:
                pass
        
        return results
    
    def origin_subdomain_scan(self):
        """Busca subdominios comunes que puedan exponer origin"""
        results = {}
        
        # Subdominios que a menudo no están detrás de CDN
        direct_subdomains = [
            'direct', 'origin', 'direct-connect', 'origin-server',
            'backend', 'internal', 'prod', 'production-origin',
            'origin-prod', 'origin-staging', 'staging-origin',
            'cpanel', 'whm', 'webmail', 'mail', 'ftp', 'ssh'
        ]
        
        base_domain = self.domain
        
        for prefix in direct_subdomains:
            try:
                test_subdomain = f"{prefix}.{base_domain}"
                answers = dns.resolver.resolve(test_subdomain, 'A', lifetime=DNS_TIMEOUT)
                ips = [str(rdata) for rdata in answers]
                
                # Filtrar IPs de Cloudflare
                cf_ips = self._is_cloudflare_ip(ips[0]) if ips else False
                if ips and not cf_ips:
                    results[test_subdomain] = ips
                    if self.verbose:
                        log_found(f"Origin subdomain: {test_subdomain} → {ips[0]}")
            except:
                pass
        
        return results
    
    def _is_cloudflare_ip(self, ip):
        """Verifica si una IP pertenece a Cloudflare"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            cf_ranges = [
                '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
                '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
                '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
                '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
                '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
            ]
            
            for range_cidr in cf_ranges:
                network = ipaddress.ip_network(range_cidr, strict=False)
                if ip_obj in network:
                    return True
        except:
            pass
        
        return False
    
    # ========================================================================
    # ANÁLISIS DE INFRAESTRUCTURA CLOUD
    # ========================================================================
    
    def analyze_cloud_infrastructure(self):
        """Analiza la infraestructura cloud"""
        all_ips = set()
        for ips in self.resolved.values():
            all_ips.update(ips)
        
        if not all_ips:
            log_warning("No hay IPs para analizar")
            return
        
        log_info(f"Analizando {len(all_ips)} IPs...")
        
        # Descargar rangos de cloud providers
        self.download_cloud_ranges()
        
        # Analizar cada IP
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_ip = {executor.submit(self.analyze_ip, ip): ip for ip in all_ips}
            
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    future.result()
                except Exception as e:
                    if self.verbose:
                        log_error(f"Error analizando {ip}: {e}")
        
        # Estadísticas cloud
        cloud_count = len(self.cloud_ips)
        if cloud_count > 0:
            log_cloud(f"Detectadas {cloud_count} IPs en infraestructura cloud")
            
            providers = defaultdict(int)
            for info in self.cloud_ips.values():
                providers[info['provider']] += 1
            
            for provider, count in providers.items():
                log_cloud(f"  {provider}: {count} IPs")
    
    def download_cloud_ranges(self):
        """Descarga rangos IP de proveedores cloud"""
        self.cloud_ranges = {}
        
        for provider_key, provider_data in CLOUD_PROVIDERS.items():
            try:
                log_info(f"Descargando rangos de {provider_data['name']}...")
                
                if provider_key == 'gcp':
                    resp = self.session.get(provider_data['ranges_url'], timeout=10)
                    data = resp.json()
                    ranges = []
                    for prefix in data.get('prefixes', []):
                        if 'ipv4Prefix' in prefix:
                            ranges.append(prefix['ipv4Prefix'])
                    self.cloud_ranges[provider_key] = ranges
                    
                elif provider_key == 'aws':
                    resp = self.session.get(provider_data['ranges_url'], timeout=10)
                    data = resp.json()
                    ranges = [item['ip_prefix'] for item in data.get('prefixes', [])]
                    self.cloud_ranges[provider_key] = ranges
                    
                elif provider_key == 'cloudflare':
                    resp = self.session.get(provider_data['ranges_url'], timeout=10)
                    ranges = [line.strip() for line in resp.text.split('\n') if line.strip()]
                    self.cloud_ranges[provider_key] = ranges
                
                log_success(f"{provider_data['name']}: {len(self.cloud_ranges.get(provider_key, []))} rangos")
                
            except Exception as e:
                if self.verbose:
                    log_error(f"Error descargando rangos de {provider_key}: {e}")
    
    def analyze_ip(self, ip):
        """Analiza una IP específica"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Verificar si está en rangos cloud
            for provider_key, ranges in self.cloud_ranges.items():
                for range_cidr in ranges:
                    try:
                        network = ipaddress.ip_network(range_cidr, strict=False)
                        if ip_obj in network:
                            provider_name = CLOUD_PROVIDERS[provider_key]['name']
                            self.cloud_ips[ip] = {
                                'provider': provider_name,
                                'provider_key': provider_key,
                                'range': range_cidr
                            }
                            if self.verbose:
                                log_cloud(f"{ip} → {provider_name} ({range_cidr})")
                            return
                    except:
                        continue
            
            # Si no está en cloud ranges conocidos, obtener ASN
            asn_info = self.get_asn_info(ip)
            if asn_info:
                self.asn_info[ip] = asn_info
                
                # Detectar cloud por ASN
                for provider_key, provider_data in CLOUD_PROVIDERS.items():
                    if asn_info.get('asn') in provider_data['asn']:
                        self.cloud_ips[ip] = {
                            'provider': provider_data['name'],
                            'provider_key': provider_key,
                            'asn': asn_info['asn'],
                            'organization': asn_info.get('organization', 'Unknown')
                        }
                        if self.verbose:
                            log_cloud(f"{ip} → {provider_data['name']} (ASN: {asn_info['asn']})")
                        break
        
        except Exception as e:
            if self.verbose:
                log_error(f"Error analizando IP {ip}: {e}")
    
    def get_asn_info(self, ip):
        """Obtiene información ASN de una IP"""
        try:
            # Usar servicios gratuitos para lookup ASN
            urls = [
                f"https://ipinfo.io/{ip}/json",
                f"https://api.hackertarget.com/aslookup/?q={ip}"
            ]
            
            for url in urls:
                try:
                    resp = self.session.get(url, timeout=5)
                    if resp.status_code == 200:
                        if 'ipinfo.io' in url:
                            data = resp.json()
                            if 'org' in data:
                                asn_match = re.search(r'AS(\d+)', data['org'])
                                if asn_match:
                                    return {
                                        'asn': f"AS{asn_match.group(1)}",
                                        'organization': data.get('org', ''),
                                        'country': data.get('country', ''),
                                        'city': data.get('city', '')
                                    }
                        else:
                            # hackertarget format
                            text = resp.text.strip()
                            if text and 'Error' not in text:
                                parts = text.split(',')
                                if len(parts) >= 2:
                                    return {
                                        'asn': parts[0].strip().strip('"'),
                                        'organization': parts[1].strip().strip('"') if len(parts) > 1 else ''
                                    }
                except:
                    continue
        except:
            pass
        
        return None
    
    # ========================================================================
    # VALIDACIÓN ACTIVA
    # ========================================================================
    
    def validate_alive(self):
        """Valida hosts activos HTTP/HTTPS"""
        log_info(f"Validando hosts activos (timeout: {self.timeout}s)...")
        
        targets = list(self.subdomains)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_target = {executor.submit(self.check_http, target): target 
                              for target in targets}
            
            completed = 0
            total = len(targets)
            
            for future in concurrent.futures.as_completed(future_to_target):
                completed += 1
                target = future_to_target[future]
                
                if self.verbose:
                    print(f"\r{Colors.BLUE}[*]{Colors.NC} Progreso: {completed}/{total} ({len(self.alive_hosts)} vivos)", 
                          end='', flush=True)
                
                try:
                    result = future.result()
                    if result:
                        self.alive_hosts.add(result['url'])
                        self.http_status[result['url']] = result['status']
                        self.technologies[target] = result.get('tech', {})
                        
                        if self.verbose:
                            print()  # Nueva línea
                            tech_str = ', '.join(result.get('tech', {}).keys()) or 'Unknown'
                            status = result['status']
                            
                            # Colorear status code
                            if 200 <= status < 300:
                                status_color = Colors.GREEN
                            elif 300 <= status < 400:
                                status_color = Colors.CYAN
                            elif 400 <= status < 500:
                                status_color = Colors.YELLOW
                            else:
                                status_color = Colors.RED
                            
                            log_alive(f"{result['url']} [{status_color}{status}{Colors.NC}] - {tech_str}")
                
                except Exception as e:
                    if self.verbose:
                        print()
                        log_error(f"Error validando {target}: {e}")
        
        if self.verbose:
            print()  # Nueva línea final
        
        log_success(f"Hosts HTTP/HTTPS activos: {len(self.alive_hosts)}")
    
    def check_http(self, subdomain):
        """Verifica si un host responde HTTP/HTTPS"""
        for protocol in ['https', 'http']:
            url = f"{protocol}://{subdomain}"
            try:
                resp = self.session.get(
                    url, 
                    timeout=self.timeout, 
                    allow_redirects=True,
                    verify=False
                )
                
                # Capturar SIEMPRE el status code
                status_code = resp.status_code
                
                # Determinar si es exitoso (2xx, 3xx, 4xx son "vivos")
                is_alive = status_code < 500
                
                if is_alive:
                    # Detectar tecnologías
                    tech = self.detect_technologies(resp)
                    
                    return {
                        'url': url,
                        'status': status_code,
                        'tech': tech,
                        'content_length': len(resp.content),
                        'redirect_url': resp.url if resp.url != url else ''
                    }
            except:
                continue
        
        return None
    
    def detect_technologies(self, response):
        """Detecta tecnologías web basándose en headers y contenido"""
        tech = {}
        
        headers = response.headers
        content = response.text[:5000]  # Primeros 5KB
        
        # Server header
        if 'Server' in headers:
            tech['Server'] = headers['Server']
        
        # X-Powered-By
        if 'X-Powered-By' in headers:
            tech['Powered-By'] = headers['X-Powered-By']
        
        # Cloud platform detection
        if 'X-Cloud-Trace-Context' in headers or 'X-Goog-' in str(headers):
            tech['Platform'] = 'Google Cloud Platform'
        elif 'X-Amz-' in str(headers) or 'X-Amzn-' in str(headers):
            tech['Platform'] = 'Amazon Web Services'
        elif 'X-Azure-' in str(headers):
            tech['Platform'] = 'Microsoft Azure'
        elif 'CF-' in str(headers) or 'cloudflare' in str(headers).lower():
            tech['Platform'] = 'Cloudflare'
        
        # Common frameworks
        patterns = {
            'WordPress': r'wp-content|wp-includes',
            'Drupal': r'Drupal|drupal',
            'Joomla': r'joomla|com_content',
            'React': r'react|__REACT',
            'Angular': r'ng-app|angular',
            'Vue.js': r'vue\.js|__VUE__',
            'Laravel': r'laravel',
            'Django': r'csrfmiddlewaretoken|django',
            'Flask': r'flask',
            'Express': r'express',
            'Spring': r'spring',
            'ASP.NET': r'__VIEWSTATE|ASP\.NET'
        }
        
        for name, pattern in patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                tech['Framework'] = name
                break
        
        return tech
    
    # ========================================================================
    # GENERACIÓN DE REPORTES
    # ========================================================================
    
    def generate_reports(self):
        """Genera todos los reportes y exportaciones"""
        log_info("Generando reportes...")
        
        # 1. Archivo de subdominios
        subdomains_file = self.output_dir / "all_subdomains.txt"
        with open(subdomains_file, 'w') as f:
            for sub in sorted(self.subdomains):
                f.write(f"{sub}\n")
        log_success(f"Subdominios: {subdomains_file}")
        
        # 2. Archivo de resolución DNS
        resolved_file = self.output_dir / "resolved.txt"
        with open(resolved_file, 'w') as f:
            for subdomain, ips in sorted(self.resolved.items()):
                for ip in ips:
                    f.write(f"{subdomain}|{ip}\n")
        log_success(f"Resueltos: {resolved_file}")
        
        # 3. IPs únicas
        ips_file = self.output_dir / "ips_unique.txt"
        all_ips = set()
        for ips in self.resolved.values():
            all_ips.update(ips)
        with open(ips_file, 'w') as f:
            for ip in sorted(all_ips):
                f.write(f"{ip}\n")
        log_success(f"IPs únicas: {ips_file}")
        
        # 4. Hosts activos
        if self.alive_hosts:
            alive_file = self.output_dir / "http_alive.txt"
            with open(alive_file, 'w') as f:
                for url in sorted(self.alive_hosts):
                    f.write(f"{url}\n")
            log_success(f"Hosts activos: {alive_file}")
            
            # 4.5 Status codes
            status_file = self.output_dir / "http_status_codes.txt"
            with open(status_file, 'w') as f:
                f.write("# URL | Status Code\n")
                for url in sorted(self.alive_hosts):
                    status = self.http_status.get(url, 'Unknown')
                    f.write(f"{url} | {status}\n")
            log_success(f"Status codes: {status_file}")
        
        # 5. Infraestructura cloud
        if self.cloud_ips:
            cloud_file = self.output_dir / "cloud_infrastructure.json"
            with open(cloud_file, 'w') as f:
                json.dump(self.cloud_ips, f, indent=2)
            log_success(f"Cloud IPs: {cloud_file}")
            
            # CSV para cloud
            cloud_csv = self.output_dir / "cloud_infrastructure.csv"
            with open(cloud_csv, 'w') as f:
                f.write("IP,Provider,Details\n")
                for ip, info in sorted(self.cloud_ips.items()):
                    provider = info.get('provider', 'Unknown')
                    details = info.get('range', info.get('asn', ''))
                    f.write(f"{ip},{provider},{details}\n")
            log_success(f"Cloud CSV: {cloud_csv}")
        
        # 6. ASN info
        if self.asn_info:
            asn_file = self.output_dir / "asn_information.json"
            with open(asn_file, 'w') as f:
                json.dump(self.asn_info, f, indent=2)
            log_success(f"ASN info: {asn_file}")
        
        # 7. IPs Origin (detrás de CDN/Proxy)
        if hasattr(self, 'origin_ips') and self.origin_ips:
            origin_file = self.output_dir / "origin_ips.txt"
            origin_json = self.output_dir / "origin_ips.json"
            
            with open(origin_file, 'w') as f:
                for subdomain, ips in sorted(self.origin_ips.items()):
                    for ip in ips:
                        f.write(f"{subdomain}|{ip}\n")
            
            with open(origin_json, 'w') as f:
                json.dump(self.origin_ips, f, indent=2)
            
            log_success(f"IPs Origin: {origin_file}")
            log_warning(f"⚠️  {len(self.origin_ips)} subdominios con IPs origin expuestas")
        
        # 8. Tecnologías detectadas
        if self.technologies:
            tech_file = self.output_dir / "technologies.json"
            with open(tech_file, 'w') as f:
                json.dump(self.technologies, f, indent=2)
            log_success(f"Tecnologías: {tech_file}")
        
        # 8. Reporte principal TXT
        self.generate_main_report()
        
        # 9. Exportaciones para herramientas
        self.generate_tool_exports()
    
    def generate_main_report(self):
        """Genera el reporte principal en texto"""
        report_file = self.output_dir / "REPORT.txt"
        
        with open(report_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("           SUBHUNTER PRO v4.0 - REPORTE DE RECONOCIMIENTO\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Dominio objetivo: {self.domain}\n")
            f.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Threads: {self.threads}\n")
            f.write(f"Timeout: {self.timeout}s\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("                         RESUMEN EJECUTIVO\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Subdominios encontrados:     {len(self.subdomains)}\n")
            f.write(f"Subdominios resueltos:       {len(self.resolved)}\n")
            
            all_ips = set()
            for ips in self.resolved.values():
                all_ips.update(ips)
            f.write(f"IPs únicas:                  {len(all_ips)}\n")
            
            f.write(f"Hosts HTTP activos:          {len(self.alive_hosts)}\n")
            f.write(f"IPs en cloud:                {len(self.cloud_ips)}\n\n")
            
            if self.cloud_ips:
                f.write("=" * 80 + "\n")
                f.write("                    INFRAESTRUCTURA CLOUD DETECTADA\n")
                f.write("=" * 80 + "\n\n")
                
                providers = defaultdict(list)
                for ip, info in self.cloud_ips.items():
                    providers[info['provider']].append(ip)
                
                for provider, ips in sorted(providers.items()):
                    f.write(f"{provider}:\n")
                    for ip in sorted(ips):
                        details = self.cloud_ips[ip]
                        extra = details.get('range', details.get('asn', ''))
                        f.write(f"  - {ip} ({extra})\n")
                    f.write("\n")
            
            if self.alive_hosts:
                f.write("=" * 80 + "\n")
                f.write("                         HOSTS ACTIVOS (TOP 50)\n")
                f.write("=" * 80 + "\n\n")
                
                for url in sorted(list(self.alive_hosts)[:50]):
                    subdomain = urlparse(url).netloc
                    tech = self.technologies.get(subdomain, {})
                    tech_str = ', '.join([f"{k}: {v}" for k, v in tech.items()]) if tech else 'Unknown'
                    f.write(f"{url}\n  Tech: {tech_str}\n\n")
            
            f.write("=" * 80 + "\n")
            f.write(f"Reporte generado por SubHunter Pro v{VERSION}\n")
            f.write("=" * 80 + "\n")
        
        log_success(f"Reporte principal: {report_file}")
    
    def generate_tool_exports(self):
        """Genera archivos para usar con otras herramientas"""
        
        # Para nuclei
        if self.alive_hosts:
            nuclei_file = self.output_dir / "targets_for_nuclei.txt"
            with open(nuclei_file, 'w') as f:
                for url in sorted(self.alive_hosts):
                    f.write(f"{url}\n")
            log_success(f"Targets para Nuclei: {nuclei_file}")
        
        # Para nmap
        all_ips = set()
        for ips in self.resolved.values():
            all_ips.update(ips)
        
        if all_ips:
            nmap_file = self.output_dir / "targets_for_nmap.txt"
            with open(nmap_file, 'w') as f:
                for ip in sorted(all_ips):
                    f.write(f"{ip}\n")
            log_success(f"Targets para Nmap: {nmap_file}")
        
        # JSON completo para análisis
        full_data = {
            'domain': self.domain,
            'scan_date': datetime.now().isoformat(),
            'subdomains': list(self.subdomains),
            'resolved': {k: v for k, v in self.resolved.items()},
            'alive_hosts': list(self.alive_hosts),
            'cloud_ips': self.cloud_ips,
            'asn_info': self.asn_info,
            'technologies': self.technologies,
            'statistics': {
                'total_subdomains': len(self.subdomains),
                'resolved_subdomains': len(self.resolved),
                'unique_ips': len(all_ips),
                'alive_hosts': len(self.alive_hosts),
                'cloud_ips': len(self.cloud_ips)
            }
        }
        
        json_file = self.output_dir / "full_scan_data.json"
        with open(json_file, 'w') as f:
            json.dump(full_data, f, indent=2)
        log_success(f"Datos completos JSON: {json_file}")
        
        # EXPORTACIÓN COMPLETA - CSV y/o JSON con TODA la información
        self.generate_complete_export()
    
    def generate_complete_export(self):
        """Genera exportación completa con TODA la información recolectada"""
        log_info("Generando exportación completa con toda la información...")
        
        # Construir dataset completo
        complete_data = []
        
        for subdomain in sorted(self.subdomains):
            # Información básica
            ips = self.resolved.get(subdomain, [])
            origin_ips = self.origin_ips.get(subdomain, []) if hasattr(self, 'origin_ips') else []
            
            # Combinar IPs actuales y origin
            all_ips = list(set(ips + origin_ips))
            
            for ip in all_ips if all_ips else ['']:
                is_origin = ip in origin_ips
                
                row = {
                    'subdomain': subdomain,
                    'ip': ip,
                    'is_origin_ip': 'Yes' if is_origin else 'No',
                    'http_url': '',
                    'https_url': '',
                    'http_status': '',
                    'https_status': '',
                    'is_alive': 'No',
                    'server': '',
                    'powered_by': '',
                    'framework': '',
                    'waf': '',
                    'cloud_provider': '',
                    'cloud_details': '',
                    'asn': '',
                    'asn_organization': '',
                    'asn_country': ''
                }
                
                # URLs activas y sus status codes
                http_url = f"http://{subdomain}"
                https_url = f"https://{subdomain}"
                
                if http_url in self.alive_hosts:
                    row['http_url'] = http_url
                    row['http_status'] = str(self.http_status.get(http_url, ''))
                    row['is_alive'] = 'Yes'
                
                if https_url in self.alive_hosts:
                    row['https_url'] = https_url
                    row['https_status'] = str(self.http_status.get(https_url, ''))
                    row['is_alive'] = 'Yes'
                
                # Tecnologías detectadas
                tech = self.technologies.get(subdomain, {})
                if tech:
                    row['server'] = tech.get('Server', '')
                    row['powered_by'] = tech.get('Powered-By', '')
                    row['framework'] = tech.get('Framework', '')
                    row['waf'] = tech.get('WAF', '')
                    
                    # Si hay plataforma cloud detectada por headers
                    if 'Platform' in tech:
                        row['cloud_provider'] = tech['Platform']
                
                # WAF detectado
                if subdomain in self.waf_results:
                    waf_data = self.waf_results[subdomain]
                    row['waf'] = waf_data.get('waf', '')
                
                # Información de cloud por IP
                if ip and ip in self.cloud_ips:
                    cloud_info = self.cloud_ips[ip]
                    row['cloud_provider'] = cloud_info.get('provider', '')
                    
                    # Detalles adicionales
                    details = []
                    if 'range' in cloud_info:
                        details.append(f"Range: {cloud_info['range']}")
                    if 'asn' in cloud_info:
                        details.append(f"ASN: {cloud_info['asn']}")
                    if 'organization' in cloud_info:
                        details.append(f"Org: {cloud_info['organization']}")
                    
                    row['cloud_details'] = ', '.join(details)
                
                # Información de ASN
                if ip and ip in self.asn_info:
                    asn_data = self.asn_info[ip]
                    row['asn'] = asn_data.get('asn', '')
                    row['asn_organization'] = asn_data.get('organization', '')
                    row['asn_country'] = asn_data.get('country', '')
                
                complete_data.append(row)
        
        # Exportar según formato elegido
        if self.export_format in ['csv', 'both']:
            self.export_complete_csv(complete_data)
        
        if self.export_format in ['json', 'both']:
            self.export_complete_json(complete_data)
    
    def export_complete_csv(self, data):
        """Exporta toda la información a CSV"""
        csv_file = self.output_dir / "complete_export.csv"
        
        if not data:
            log_warning("No hay datos para exportar a CSV")
            return
        
        # Headers
        headers = [
            'Subdomain',
            'IP',
            'Is Origin IP',
            'HTTP URL',
            'HTTPS URL',
            'HTTP Status',
            'HTTPS Status',
            'Is Alive',
            'Server',
            'Powered By',
            'Framework',
            'WAF',
            'Cloud Provider',
            'Cloud Details',
            'ASN',
            'ASN Organization',
            'ASN Country'
        ]
        
        with open(csv_file, 'w', encoding='utf-8') as f:
            # Escribir headers
            f.write(','.join(headers) + '\n')
            
            # Escribir datos
            for row in data:
                values = [
                    self._escape_csv(row['subdomain']),
                    self._escape_csv(row['ip']),
                    self._escape_csv(row['is_origin_ip']),
                    self._escape_csv(row['http_url']),
                    self._escape_csv(row['https_url']),
                    self._escape_csv(row['http_status']),
                    self._escape_csv(row['https_status']),
                    self._escape_csv(row['is_alive']),
                    self._escape_csv(row['server']),
                    self._escape_csv(row['powered_by']),
                    self._escape_csv(row['framework']),
                    self._escape_csv(row['waf']),
                    self._escape_csv(row['cloud_provider']),
                    self._escape_csv(row['cloud_details']),
                    self._escape_csv(row['asn']),
                    self._escape_csv(row['asn_organization']),
                    self._escape_csv(row['asn_country'])
                ]
                f.write(','.join(values) + '\n')
        
        log_success(f"Exportación completa CSV: {csv_file} ({len(data)} registros)")
    
    def export_complete_json(self, data):
        """Exporta toda la información a JSON"""
        json_file = self.output_dir / "complete_export.json"
        
        export_data = {
            'metadata': {
                'domain': self.domain,
                'scan_date': datetime.now().isoformat(),
                'total_records': len(data),
                'export_format': 'complete',
                'includes': [
                    'subdomains',
                    'ips',
                    'http_status',
                    'technologies',
                    'cloud_provider',
                    'asn_information'
                ]
            },
            'data': data
        }
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        log_success(f"Exportación completa JSON: {json_file} ({len(data)} registros)")
    
    def _escape_csv(self, value):
        """Escapa valores para CSV"""
        if not value:
            return ''
        
        value = str(value)
        
        # Si contiene coma, comillas o salto de línea, envolver en comillas
        if ',' in value or '"' in value or '\n' in value:
            value = '"' + value.replace('"', '""') + '"'
        
        return value
    
    def print_statistics(self):
        """Imprime estadísticas finales"""
        all_ips = set()
        for ips in self.resolved.values():
            all_ips.update(ips)
        
        print()
        print(f"{Colors.CYAN}╔════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}        {Colors.YELLOW}ESTADÍSTICAS FINALES{Colors.NC}        {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}╠════════════════════════════════════════╣{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC} Subdominios:         {Colors.GREEN}{len(self.subdomains):>16}{Colors.NC} {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC} Resueltos:           {Colors.GREEN}{len(self.resolved):>16}{Colors.NC} {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC} IPs únicas:          {Colors.GREEN}{len(all_ips):>16}{Colors.NC} {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC} Hosts activos:       {Colors.GREEN}{len(self.alive_hosts):>16}{Colors.NC} {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC} IPs en cloud:        {Colors.GREEN}{len(self.cloud_ips):>16}{Colors.NC} {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC} Fuentes consultadas: {Colors.GREEN}{20:>16}{Colors.NC} {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}╚════════════════════════════════════════╝{Colors.NC}")
        print()
        
        log_success(f"Resultados guardados en: {Colors.YELLOW}{self.output_dir}{Colors.NC}")
    
    # ========================================================================
    # DETECCIÓN AVANZADA DE TECNOLOGÍAS Y WAF
    # ========================================================================
    
    def detect_technologies_advanced(self):
        """Detección avanzada de tecnologías usando whatweb"""
        if not self.alive_hosts:
            log_info("No hay hosts activos para analizar tecnologías")
            return
        
        log_info("Detectando tecnologías con WhatWeb...")
        
        # Verificar si whatweb está instalado
        whatweb_available = self._check_tool_installed('whatweb')
        
        if not whatweb_available:
            log_warning("WhatWeb no está instalado")
            log_info("  Instalar: gem install whatweb (requiere ruby)")
            log_info("Usando solo detección manual de headers...")
            return
        
        self.whatweb_results = {}
        
        # Limitar a hosts activos para no ser muy lento
        targets = list(self.alive_hosts)[:50]  # Máximo 50 hosts
        
        log_info(f"Analizando {len(targets)} hosts con WhatWeb...")
        
        for url in targets:
            try:
                subdomain = url.replace('https://', '').replace('http://', '').split('/')[0]
                
                # Ejecutar whatweb
                cmd = f"whatweb -a 3 --color=never --no-errors '{url}' 2>/dev/null"
                result = subprocess.run(cmd, shell=True, capture_output=True, 
                                      text=True, timeout=10)
                
                if result.returncode == 0 and result.stdout:
                    # Parsear salida de whatweb
                    tech_data = self._parse_whatweb_output(result.stdout)
                    
                    if tech_data:
                        self.whatweb_results[subdomain] = tech_data
                        
                        # Actualizar technologies con info de whatweb
                        if subdomain not in self.technologies:
                            self.technologies[subdomain] = {}
                        
                        self.technologies[subdomain].update(tech_data)
                        
                        if self.verbose:
                            techs = ', '.join([f"{k}:{v}" for k,v in list(tech_data.items())[:3]])
                            log_found(f"{subdomain}: {techs}")
            
            except subprocess.TimeoutExpired:
                if self.verbose:
                    log_error(f"Timeout en whatweb para {url}")
            except Exception as e:
                if self.verbose:
                    log_error(f"Error whatweb en {url}: {str(e)}")
        
        log_success(f"WhatWeb completado: {len(self.whatweb_results)} hosts analizados")
    
    def detect_waf(self):
        """Detección de WAF usando wafw00f"""
        if not self.alive_hosts:
            log_info("No hay hosts activos para detectar WAF")
            return
        
        log_info("Detectando WAF con wafw00f...")
        
        # Verificar si wafw00f está instalado
        wafw00f_available = self._check_tool_installed('wafw00f')
        
        if not wafw00f_available:
            log_warning("wafw00f no está instalado")
            log_info("  Instalar: pip3 install wafw00f --break-system-packages")
            log_info("Saltando detección de WAF...")
            return
        
        self.waf_results = {}
        
        # Analizar solo HTTPS (donde hay WAF típicamente)
        https_targets = [url for url in self.alive_hosts if url.startswith('https://')][:30]
        
        if not https_targets:
            log_info("No hay hosts HTTPS para detectar WAF")
            return
        
        log_info(f"Analizando {len(https_targets)} hosts HTTPS con wafw00f...")
        
        for url in https_targets:
            try:
                subdomain = url.replace('https://', '').replace('http://', '').split('/')[0]
                
                # Ejecutar wafw00f
                cmd = f"wafw00f '{url}' -a 2>/dev/null"
                result = subprocess.run(cmd, shell=True, capture_output=True, 
                                      text=True, timeout=15)
                
                if result.returncode == 0 and result.stdout:
                    # Parsear salida de wafw00f
                    waf_info = self._parse_wafw00f_output(result.stdout)
                    
                    if waf_info and waf_info['waf'] != 'None':
                        self.waf_results[subdomain] = waf_info
                        
                        # Actualizar technologies con info de WAF
                        if subdomain not in self.technologies:
                            self.technologies[subdomain] = {}
                        
                        self.technologies[subdomain]['WAF'] = waf_info['waf']
                        
                        if self.verbose:
                            log_found(f"{subdomain}: WAF = {waf_info['waf']}")
            
            except subprocess.TimeoutExpired:
                if self.verbose:
                    log_error(f"Timeout en wafw00f para {url}")
            except Exception as e:
                if self.verbose:
                    log_error(f"Error wafw00f en {url}: {str(e)}")
        
        # Estadísticas de WAF
        waf_count = len(self.waf_results)
        if waf_count > 0:
            log_warning(f"⚠️  WAF detectado en {waf_count} hosts")
            
            # Mostrar resumen de WAFs
            waf_types = {}
            for waf_data in self.waf_results.values():
                waf_name = waf_data['waf']
                waf_types[waf_name] = waf_types.get(waf_name, 0) + 1
            
            for waf_name, count in sorted(waf_types.items(), key=lambda x: x[1], reverse=True):
                log_info(f"  • {waf_name}: {count} hosts")
        else:
            log_success("No se detectaron WAFs en los hosts analizados")
    
    def _check_tool_installed(self, tool):
        """Verifica si una herramienta está instalada"""
        try:
            result = subprocess.run(f"which {tool}", shell=True, capture_output=True)
            return result.returncode == 0
        except:
            return False
    
    def _parse_whatweb_output(self, output):
        """Parsea la salida de whatweb"""
        tech_data = {}
        
        try:
            # WhatWeb output format: URL [Status, Title, Technologies]
            # Ejemplo: http://example.com [200 OK] Apache[2.4.41], PHP[7.4.3]
            
            # Buscar tecnologías comunes
            patterns = {
                'Server': r'(Apache|Nginx|IIS|LiteSpeed|OpenResty|Caddy|Tomcat|Undertow)(?:\[([^\]]+)\])?',
                'Language': r'(PHP|Python|Ruby|Java|ASP\.NET|Node\.js|Go|Perl)(?:\[([^\]]+)\])?',
                'Framework': r'(WordPress|Drupal|Joomla|Laravel|Django|Rails|Express|Flask|Spring)',
                'CMS': r'(WordPress|Drupal|Joomla|Magento|Shopify|PrestaShop|Wix|Squarespace)',
                'CDN': r'(Cloudflare|Akamai|Fastly|Amazon CloudFront|KeyCDN|StackPath)',
                'Analytics': r'(Google Analytics|Matomo|Adobe Analytics|Mixpanel)',
                'JavaScript': r'(jQuery|Bootstrap|React|Angular|Vue\.js|Ember|Backbone)',
            }
            
            for category, pattern in patterns.items():
                matches = re.findall(pattern, output, re.IGNORECASE)
                if matches:
                    values = []
                    for match in matches:
                        if isinstance(match, tuple):
                            name = match[0]
                            version = match[1] if len(match) > 1 and match[1] else ''
                            values.append(f"{name} {version}".strip())
                        else:
                            values.append(match)
                    
                    if values:
                        tech_data[category] = ', '.join(values) if len(values) > 1 else values[0]
            
            # Extraer título
            title_match = re.search(r'Title:\s*([^\[,\n]+)', output)
            if title_match:
                tech_data['Title'] = title_match.group(1).strip()
            
            # Extraer HTTPServer específico
            server_match = re.search(r'HTTPServer\[([^\]]+)\]', output)
            if server_match and 'Server' not in tech_data:
                tech_data['Server'] = server_match.group(1)
            
            # Extraer X-Powered-By
            powered_match = re.search(r'X-Powered-By\[([^\]]+)\]', output)
            if powered_match:
                tech_data['Powered-By'] = powered_match.group(1)
        
        except Exception as e:
            pass
        
        return tech_data
    
    def _parse_wafw00f_output(self, output):
        """Parsea la salida de wafw00f"""
        waf_info = {'waf': 'None', 'details': ''}
        
        try:
            # wafw00f output examples:
            # [*] The site https://example.com is behind Cloudflare (Cloudflare Inc.)
            # [*] The site https://example.com is behind a WAF or security solution
            # [*] Generic Detection results:
            
            # Buscar WAF detectado
            waf_patterns = [
                r'is behind ([^(]+)',
                r'Detected:\s*(.+?)(?:\n|\(|$)',
                r'The website is behind\s+(.+?)(?:\n|$)',
            ]
            
            for pattern in waf_patterns:
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    waf_name = match.group(1).strip()
                    if waf_name and waf_name.lower() not in ['a waf or security solution', 'nothing']:
                        waf_info['waf'] = waf_name
                        break
            
            # Buscar detalles adicionales
            if '(' in output and ')' in output:
                details_match = re.search(r'\(([^)]+)\)', output)
                if details_match:
                    waf_info['details'] = details_match.group(1)
            
            # Casos específicos conocidos
            waf_keywords = {
                'cloudflare': 'Cloudflare',
                'akamai': 'Akamai',
                'aws': 'AWS WAF',
                'imperva': 'Imperva',
                'incapsula': 'Imperva Incapsula',
                'f5': 'F5 BIG-IP',
                'barracuda': 'Barracuda',
                'fortinet': 'FortiWeb',
                'fortiweb': 'FortiWeb',
                'sucuri': 'Sucuri',
                'wordfence': 'Wordfence',
                'modsecurity': 'ModSecurity',
                'wallarm': 'Wallarm',
            }
            
            output_lower = output.lower()
            for keyword, waf_name in waf_keywords.items():
                if keyword in output_lower and waf_info['waf'] == 'None':
                    waf_info['waf'] = waf_name
                    break
        
        except Exception as e:
            pass
        
        return waf_info

# ============================================================================
# MAIN
# ============================================================================

def main():
    print(Colors.RED + BANNER + Colors.NC)
    
    parser = argparse.ArgumentParser(
        description='SubHunter Pro v4.0 - Advanced Infrastructure Discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  %(prog)s -d example.com
  %(prog)s -d example.com -t 100 -v
  %(prog)s -d example.com -o /tmp/scan --skip-active
  %(prog)s -d example.com --skip-cloud -t 200
  %(prog)s -d example.com --export-format csv
  %(prog)s -d example.com --export-format json -v
        """
    )
    
    parser.add_argument('-d', '--domain', required=True, 
                       help='Dominio objetivo')
    parser.add_argument('-o', '--output', 
                       help='Directorio de salida')
    parser.add_argument('-t', '--threads', type=int, default=50,
                       help='Número de threads (default: 50)')
    parser.add_argument('-T', '--timeout', type=int, default=5,
                       help='Timeout en segundos (default: 5)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Modo verbose')
    parser.add_argument('--skip-active', action='store_true',
                       help='Saltar validación activa de hosts')
    parser.add_argument('--skip-cloud', action='store_true',
                       help='Saltar análisis de infraestructura cloud')
    parser.add_argument('--export-format', choices=['csv', 'json', 'both'], default='both',
                       help='Formato de exportación completa: csv, json o both (default: both)')
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    
    args = parser.parse_args()
    
    # Determinar directorio de salida
    if args.output:
        output_dir = args.output
    else:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        domain_clean = args.domain.replace('.', '_')
        output_dir = f"./subhunter_{domain_clean}_{timestamp}"
    
    # Desactivar warnings SSL
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Crear instancia y ejecutar
    hunter = SubHunter(
        domain=args.domain,
        output_dir=output_dir,
        threads=args.threads,
        timeout=args.timeout,
        verbose=args.verbose,
        skip_active=args.skip_active,
        skip_cloud=args.skip_cloud,
        export_format=args.export_format
    )
    
    try:
        hunter.run()
    except KeyboardInterrupt:
        print()
        log_warning("Escaneo interrumpido por el usuario")
        sys.exit(1)
    except Exception as e:
        log_error(f"Error fatal: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
