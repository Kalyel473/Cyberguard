# 🛡️ CyberGuard Pentest Suite v3.0

## Ferramenta Profissional de Cibersegurança Web & Bug Hunter

**CyberGuard** é uma suite completa de testes de penetração web (web pentest) e descoberta de vulnerabilidades, desenvolvida para profissionais de cibersegurança, pentestadores e bug hunters. A ferramenta integra reconhecimento avançado, scanning de vulnerabilidades profundas, fuzzing inteligente, análise de tokens JWT, detecção de SSTI e muito mais.

---

## 📋 Índice

- [Características Principais](#características-principais)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Como Usar](#como-usar)
- [Funcionalidades Detalhadas](#funcionalidades-detalhadas)
- [Estrutura de Saída](#estrutura-de-saída)
- [Exemplos de Uso](#exemplos-de-uso)
- [Integrações](#integrações)
- [Avisos Legais](#avisos-legais)
- [Troubleshooting](#troubleshooting)

---

## 🚀 Características Principais

### Reconhecimento Avançado
- ✅ **Enumeração de Subdomínios** (bruteforce DNS, Certificate Transparency, zone transfer)
- ✅ **Scanning de Portas** (Nmap integrado + scanner TCP básico)
- ✅ **Enumeração DNS** (A, AAAA, MX, NS, TXT, SOA, CNAME, PTR reverso)
- ✅ **WHOIS Lookup** (informações de registro de domínio)
- ✅ **Technology Fingerprinting** (detecção de frameworks, servidores, libs)
- ✅ **SSL/TLS Certificate Analysis** (validade, SANs, detecção de expiração próxima)
- ✅ **Security Headers Check** (HSTS, CSP, X-Frame-Options, etc.)
- ✅ **WAF Detection** (Cloudflare, AWS, Imperva, ModSecurity, etc.)
- ✅ **Email Harvesting** (coleta de endereços de email públicos)
- ✅ **Web Crawling** (coleta automática de links e formulários)

### Scanning de Vulnerabilidades
- 🔴 **SQL Injection** (detecção de erros + blind SQLi com timing)
- 🔴 **Cross-Site Scripting (XSS)** (Reflected + formulários)
- 🔴 **Command Injection** (análise de output)
- 🔴 **File Inclusion** (LFI/RFI com detecção de conteúdo)
- 🔴 **IDOR** (Insecure Direct Object Reference)
- 🔴 **CSRF** (detecção de formulários sem CSRF token)
- 🔴 **CORS Misconfiguration** (wildcard + reflect-based)
- 🔴 **SSRF** (Server-Side Request Forgery)
- 🔴 **Open Redirect**
- 🔴 **Clickjacking** (falta de X-Frame-Options)
- 🔴 **Subdomain Takeover** (CNAME orphaned)
- 🔴 **HTTP Methods** (TRACE, PUT, DELETE, etc.)
- 🔴 **Insecure Cookie Attributes** (missing Secure, HttpOnly, SameSite)
- 🔴 **Sensitive Info Exposure** (AWS keys, private keys, JWT tokens)
- 🔴 **Exposed Git** (.git, .env públicos)
- 🔴 **Rate Limiting** (detecção de proteção 429)

### Funcionalidades Avançadas (Deep Pentest)
- 🎯 **Autenticação via Formulário** (preserva sessão, testa acesso autenticado)
- 🎯 **Deep Parameter Fuzzing** (time-based SQLi, XSS, SSTI, LFI)
- 🎯 **SSTI Detection** (Template Injection em Jinja2, ERB, etc.)
- 🎯 **JWT Token Analysis** (alg=none, missing exp, payload inspection)
- 🎯 **JavaScript Rendering** (Playwright para detecção de DOM sinks + XSS)
- 🎯 **Shodan Lookup** (enriquecimento com dados públicos, se chave disponível)

### Geração de Relatórios & Persistência
- 📊 **Relatórios HTML Interativos** (com dashboard de severidade)
- 📊 **Relatórios JSON** (integração com outros tools)
- 📊 **Export CSV** (vulnerabilidades em formato tabular)
- 📊 **SQLite Persistence** (todas as vulns salvas em DB, deduplicadas)
- 📊 **Armazenamento de Evidências** (response text, headers, screenshots)
- 📊 **Email Integration** (envio de relatórios via SMTP)

---

## 📦 Requisitos

### Mínimos
- **Python 3.8+**
- **pip** (gerenciador de pacotes)
- **Conexão com a internet**

### Recomendados
- **Nmap** instalado (para scanning profissional de portas)
- **Playwright** (para JS rendering + headless browser)
- **curl/wget** (para requisições auxiliares)

### Optionais
- **Shodan API Key** (para enriquecimento de dados — defina `SHODAN_API_KEY` env var)
- **Credenciais SMTP** (para envio de relatórios por email)

---

## ⚙️ Instalação

### 1. Clone ou baixe a ferramenta
```bash
git clone https://github.com/seu-repo/cyberguard.git
cd cyberguard
```

### 2. Instale as dependências
```bash
pip install -r requirements.txt
```

**Ou instale manualmente:**
```bash
pip install requests beautifulsoup4 colorama dnspython whois paramiko pyyaml cryptography pyjwt aiohttp
```

### 3. (Opcional) Instale Nmap
- **Windows:** https://nmap.org/download.html
- **macOS:** `brew install nmap`
- **Linux:** `sudo apt-get install nmap`

### 4. (Opcional) Instale Playwright
```bash
pip install playwright
playwright install chromium
```

### 5. (Opcional) Configure variáveis de ambiente
```bash
# Para Shodan
export SHODAN_API_KEY="seu_api_key_aqui"

# Para SMTP (opcional, será solicitado durante execução)
# Não armazene credenciais em variáveis de ambiente em produção
```

---

## 🎯 Como Usar

### Execução Básica
```bash
python Cyberguard.py
```

### Fluxo Interativo
1. **Aceite o aviso legal** (confirme com `s`)
2. **Digite a URL alvo** (ex: `https://example.com` ou `example.com`)
3. **Escolha o diretório de saída** (padrão: `pentest_reports`)
4. **Navegue pelo menu** e escolha as operações desejadas

### Exemplos de Menu

#### Opção 1: Reconhecimento Avançado
```
[*] Iniciando reconhecimento avançado
[*] Bruteforce DNS...
[*] Consultando Certificate Transparency logs...
[*] Tentando transferência de zona DNS...
[*] Escaneando portas...
[*] Identificando tecnologias...
[*] Verificando certificado SSL...
[*] Analisando headers de segurança...
[*] Consultando WHOIS...
[*] Crawling do site...
[*] Verificando WAF...
[*] Coletando emails...
```

#### Opção 2: Scanner de Vulnerabilidades
```
[*] Iniciando scanner de vulnerabilidades
  → SQL Injection
  → XSS
  → Command Injection
  → File Inclusion
  → IDOR
  → CSRF
  → CORS
  → SSRF
  → Open Redirect
  → Clickjacking
  → Subdomain Takeover
  → HTTP Methods
  → Cookie Analysis
  → Sensitive Info
  → Exposed Git
  → Rate Limiting
```

#### Opção 11: Deep Fuzz (Parâmetros)
```
[?] Máximo de testes (padrão 1000): 5000
[*] Fuzzing com payloads:
    - ' OR '1'='1' --
    - <script>alert('XSS')</script>
    - {{7*7}}
    - ../../../../etc/passwd
    - '||sleep(5)--
[+] Fuzzing concluído (5000 testes)
```

---

## 🔍 Funcionalidades Detalhadas

### 1. Reconhecimento Avançado (`advanced_reconnaissance`)
**O que faz:** Coleta informações passivas sobre o alvo
**Saídas:**
- `pentest_reports/scans/dns_info.json` — registros DNS
- `pentest_reports/scans/open_ports.json` — portas abertas
- `pentest_reports/scans/technologies.json` — frameworks detectados
- `pentest_reports/scans/ssl_certificate.json` — info de SSL
- `pentest_reports/scans/security_headers.json` — análise de headers
- `pentest_reports/scans/whois_info.json` — informações WHOIS
- `pentest_reports/scans/waf_detection.json` — WAF detectado
- `pentest_reports/loot/active_subdomains.txt` — subdomínios ativos
- `pentest_reports/loot/crawled_links.txt` — links coletados
- `pentest_reports/loot/emails.txt` — emails encontrados

### 2. Scanner de Vulnerabilidades (`vulnerability_scan`)
**O que faz:** Testa o alvo contra 16 classes de vulnerabilidades comuns
**Saídas:**
- `pentest_reports/scans/vulnerability_report.json` — todas as vulns
- `pentest_reports/loot/vuln_evidence/` — textos de resposta (para análise)
- `pentest_reports/scans/vulns.db` — banco SQLite com histórico

### 3. Enumeração de Diretórios (`directory_enumeration`)
**O que faz:** Bruteforce de diretórios e arquivos comuns
**Saídas:**
- `pentest_reports/scans/directory_enumeration.json` — lista detalhada
- Console output: paths com status (200, 403, 401, redirect)

### 4. Autenticação via Formulário (`authenticate_via_form`)
**O que faz:** Tenta fazer login automaticamente e preserva a sessão
**Exemplo:**
```
[?] Login URL: https://example.com/login
[?] Campo usuário (name): username
[?] Campo senha (name): password
[?] Username: attacker@example.com
[?] Password: senha123
[+] Autenticação aparentemente bem sucedida
Cookies salvos em: pentest_reports/loot/auth_cookies.txt
```

### 5. Deep Fuzz (`fuzz_parameters`)
**O que faz:** Testa todos os parâmetros GET/POST com payloads maliciosos
**Detecta:**
- Reflected parameters (payload no response)
- Blind SQL Injection (timing attacks)
- Server-Side Template Injection (SSTI)
- Local File Inclusion (LFI)
**Saídas:** Vulnerabilidades adicionadas ao DB + console log

### 6. SSTI Check (`check_ssti`)
**O que faz:** Procura Server-Side Template Injection
**Exemplo Payload:** `{{7*7}}` → se resposta conter `49`, há SSTI
**Engines Testadas:** Jinja2, ERB, Velocity, Freemarker, etc.

### 7. JWT Analysis (`check_jwt_tokens`)
**O que faz:** Procura JWTs em páginas e analisa segurança
**Detecta:**
- `alg=none` (sem assinatura)
- Falta de `exp` claim (expiração)
- Payloads decodificáveis
**Saídas:** Tokens e issues salvos em vulnerabilities

### 8. JS Render Crawl (`js_render_crawl`)
**O que faz:** Renderiza JavaScript com Playwright e procura DOM sinks
**Detecta:**
- `document.write()`
- `.innerHTML` / `.outerHTML`
- `eval()`
- Inline event handlers (`on*`)
**Saídas:**
- `pentest_reports/scans/js_rendered_pages.json`
- `pentest_reports/scans/dom_sinks.json`

### 9. Geração de Relatórios (`generate_comprehensive_report`)
**O que faz:** Compila todos os dados em um relatório HTML/JSON
**Saídas:**
- `pentest_reports/reports/full_report_YYYYMMDD_HHMMSS.html` (interativo)
- `pentest_reports/reports/full_report_YYYYMMDD_HHMMSS.json` (estruturado)

---

## 📁 Estrutura de Saída

```
pentest_reports/
├── scans/
│   ├── dns_info.json
│   ├── open_ports.json
│   ├── technologies.json
│   ├── ssl_certificate.json
│   ├── security_headers.json
│   ├── whois_info.json
│   ├── waf_detection.json
│   ├── vulnerability_report.json
│   ├── directory_enumeration.json
│   ├── js_rendered_pages.json
│   ├── dom_sinks.json
│   ├── shodan_lookup.json
│   └── vulns.db (SQLite)
├── loot/
│   ├── active_subdomains.txt
│   ├── crawled_links.txt
│   ├── emails.txt
│   ├── auth_cookies.txt
│   ├── vuln_evidence/
│   │   ├── {vuln_id}.txt (evidências brutass)
│   │   └── ...
│   └── ...
├── reports/
│   ├── full_report_20260131_124211.html
│   ├── full_report_20260131_124211.json
│   ├── vulnerabilities_20260131_124211.csv
│   └── ...
├── screenshots/
│   └── (para capturas de tela futuras)
└── pentest.log (log completo da execução)
```

---

## 💡 Exemplos de Uso

### Exemplo 1: Pentest Completo em um Site
```bash
$ python Cyberguard.py
[?] Digite a URL alvo: https://vulnerable-app.local
[?] Diretório de saída: pentest_reports

# Menu
1. Reconhecimento Avançado  → Recon passivo completo
2. Scanner de Vulnerabilidades → Testa 16 tipos de vulns
3. Enumeração de Diretórios  → Bruteforce de paths
4. Teste Completo           → Executa 1 + 2
6. Gerar Relatório          → HTML + JSON
7. Exportar CSV             → Para planilha
```

### Exemplo 2: Teste Autenticado
```bash
$ python Cyberguard.py
[?] Digite a URL alvo: https://example.com

# Menu
10. Autenticação via Formulário
    [?] Login URL: https://example.com/login
    [?] Campo usuário: email
    [?] Campo senha: password
    [?] Username: tester@example.com
    [?] Password: TestPass123
    [+] Autenticação bem sucedida (cookies salvos)

# Agora a sessão está autenticada para os próximos testes
2. Scanner de Vulnerabilidades (já autenticado)
11. Deep Fuzz (com credenciais)
```

### Exemplo 3: Fuzzing Agressivo
```bash
$ python Cyberguard.py
[?] Digite a URL alvo: https://api.example.com

# Menu
11. Deep Fuzz (Parâmetros)
[?] Máximo de testes: 10000

# A ferramenta vai:
# - Extrair todos os parâmetros das URLs crawleadas
# - Enviar 10.000 payloads diferentes (SQLi, XSS, SSTI, LFI)
# - Registrar reflexos, delays, e respostas anômalas
# - Salvar todas as vulns no DB
```

### Exemplo 4: Bug Bounty Rápido
```bash
# 1. Reconhecimento + Vuln Scan
python Cyberguard.py → Opção 4 (Teste Completo)

# 2. Deep Fuzz (parâmetros)
→ Opção 11

# 3. JWT Checks (se houver autenticação)
→ Opção 13

# 4. Gerar Relatório HTML
→ Opção 6

# 5. Exportar CSV (para triagem)
→ Opção 7

# Resultado: pentest_reports/reports/ com todos os findings
```

---

## 🔗 Integrações

### Shodan
```bash
export SHODAN_API_KEY="seu_api_key"
python Cyberguard.py
# Menu → Opção 9 (Consultar Shodan)
```
**Saída:** IP do alvo enriquecido com puertos, banners, histórico de vulns.

### Email (SMTP)
```bash
python Cyberguard.py
# Menu → Opção 8 (Enviar Relatório por Email)
[?] SMTP server: smtp.gmail.com
[?] SMTP port: 587
[?] Username: seu_email@gmail.com
[?] Password: sua_senha_ou_app_password
[?] From: seu_email@gmail.com
[?] To: cliente@example.com, gerente@example.com
[?] Subject: Pentest Report - example.com
```

### CSV Export
```bash
# Menu → Opção 7 (Exportar Vulnerabilidades)
# Gera: pentest_reports/reports/vulnerabilities_TIMESTAMP.csv
# Colunas: id | type | severity | url | payload | evidence | timestamp
```

---

## ⚖️ Avisos Legais

**IMPORTANTE:** Esta ferramenta é fornecida **APENAS PARA FINS EDUCACIONAIS** e **TESTES ÉTICOS DE SEGURANÇA**.

### ⚠️ Requisitos Legais
1. **Você DEVE possuir autorização EXPLÍCITA POR ESCRITO** para testar qualquer sistema
2. **Não teste sistemas que você não possui** ou não tem permissão expressa
3. **Não teste ambientes de produção** sem consentimento documentado
4. **Não use para atividades ilícitas**, roubo de dados, ou outros crimes cibernéticos
5. **O usuário é o único responsável** por todas as ações realizadas com esta ferramenta

### Responsabilidades do Desenvolvedor
- A ferramenta é fornecida "AS-IS" sem garantias
- O desenvolvedor não é responsável por danos causados pelo mau uso
- Sempre obtenha permissão documentada antes de executar testes
- Respeitemos a privacidade e as leis de cibersegurança

### Boas Práticas
- ✅ Use dentro de um ambiente controlado (teste local, staging, sandbox)
- ✅ Documente todos os testes e resultados
- ✅ Notifique responsávelmente os proprietários dos sistemas
- ✅ Siga as políticas de divulgação responsável (90 dias)
- ✅ Não divulgue exploits públicos sem permissão

---

## 🐛 Troubleshooting

### Problema: "Nmap não disponível"
**Solução:**
```bash
# Windows
# Baixe e instale em: https://nmap.org/download.html

# macOS
brew install nmap

# Linux
sudo apt-get install nmap
```

### Problema: "Playwright não disponível"
**Solução:**
```bash
pip install playwright
playwright install chromium
```

### Problema: "SSL Certificate Verification Failed"
**Solução:** A ferramenta usa `verify=False` por padrão para não desabilitar certificados auto-assinados. Se receber erro, certifique-se que o certificado é válido:
```bash
python -c "import ssl; print(ssl.create_default_context())"
```

### Problema: Timeout em Crawling
**Causa:** Site lento ou com muitas páginas
**Solução:**
- Aumente o timeout manualmente no código (padrão: 5s)
- Reduza `max_pages` em `crawl_website()`
- Use um proxy ou acesso mais rápido

### Problema: Muitas Falsos Positivos em Fuzz
**Solução:**
- Reduza o número de testes (`max_tests`)
- Filtre por severidade (apenas HIGH/CRITICAL)
- Valide manualmente as vulnerabilidades encontradas

### Problema: "SHODAN API key inválida"
**Solução:**
```bash
export SHODAN_API_KEY="sua_chave_correta"
python Cyberguard.py
```
Obtenha uma chave em: https://shodan.io

### Problema: Cookies/Sessão não Persiste
**Solução:** A ferramenta salva cookies em `pentest_reports/loot/auth_cookies.txt`. Se autenticação falhar:
1. Verifique as credenciais
2. Confirme que o formulário foi detectado
3. Tente novamente com método GET vs POST correto

---

## 📊 Casos de Uso

| Caso | Opções Recomendadas |
|------|-------------------|
| **Reconhecimento Passivo** | 1, 6 |
| **Pentest Completo** | 4, 11, 12, 13, 6 |
| **Bug Bounty Rápido** | 4, 11, 6, 7 |
| **Teste Autenticado** | 10, 2, 11, 6 |
| **Análise de API** | 1, 11, 13, 7 |
| **Avaliação de WAF** | 1, 2, 11 |
| **Coleta de Inteligência** | 1, 9 (Shodan) |

---

## 🤝 Contribuindo

Contribuições são bem-vindas! Para contribuir:
1. Faça um fork do repositório
2. Crie uma branch (`git checkout -b feature/minha-feature`)
3. Commit suas mudanças (`git commit -m "Add feature"`)
4. Push para a branch (`git push origin feature/minha-feature`)
5. Abra um Pull Request

---

## 📞 Suporte

Para dúvidas, bugs ou sugestões:
- 📧 Email: segurança@example.com
- 🐛 Issues: https://github.com/seu-repo/cyberguard/issues
- 💬 Discussions: https://github.com/seu-repo/cyberguard/discussions

---

## 📄 Licença

Este projeto é fornecido para **fins educacionais apenas**. Veja [LICENSE](LICENSE) para detalhes.

```
CYBERGUARD v3.0
Copyright © 2026 - Todos os direitos reservados
Uso apenas em sistemas autorizados
```

---

## 🎓 Recursos Educacionais

- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTheBox](https://www.hackthebox.com/)
- [TryHackMe](https://tryhackme.com/)
- [SANS Cyber Academy](https://www.sans.org/)

---

## ✨ Obrigado por usar CyberGuard!

Desenvolvido com ❤️ para a comunidade de segurança ofensiva.

**Lembre-se:** Com grande poder, vem grande responsabilidade. Use eticamente. 🛡️

---

**Última atualização:** 1 de Fevereiro de 2026  
**Versão:** 3.0  
**Status:** Production Ready
