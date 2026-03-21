# 🔒 CyberSec Toolkit v2

Toolkit de cibersegurança em **Python puro** (sem dependências externas), expandido com 4 novas
ferramentas, melhorias nas existentes e saída multi-formato (TXT / JSON / HTML).

> ⚠️ **USO ÉTICO APENAS** — Utilize somente em sistemas e redes com autorização explícita.

## 📁 Estrutura

```
CyberSec-toolkit-v2/
├── lib/common.py                  ← Biblioteca compartilhada (Reporter, cores)
├── 🆕 web_vuln_scanner/           ← XSS, SQLi, LFI, Open Redirect, CSRF, CORS, Headers
├── 🆕 osint_harvester/            ← Emails, WHOIS, DNS, Tecnologias, Redes Sociais
├── 🆕 ssl_analyzer/               ← Cert chain, TLS versions, Ciphers, HSTS, Heartbleed
├── 🆕 subdomain_takeover/         ← CNAME dangling em 30+ serviços cloud
├── port_scanner/    ✅ + OS detect, UDP scan, service version, JSON/HTML output
├── dns_recon/       ✅ + SPF/DMARC/DKIM analysis, CAA, DNSSEC
├── hash_cracker/    ✅ + NTLM, bcrypt verify, scrypt
├── password_cracker/ ✅ + NTLM, Hybrid prefix+suffix, output JSON
├── banner_grabber/
├── network_scanner/
├── packet_sniffer/
└── keylogger/
```

## 🆕 Novas Ferramentas

### Web Vulnerability Scanner
```bash
python3 web_vuln_scanner/web_vuln_scanner.py -u https://example.com --crawl --output relatorio
```
XSS | SQLi (error+time-based) | LFI | Open Redirect | Security Headers | CSRF | CORS

### OSINT / Email Harvester
```bash
python3 osint_harvester/osint_harvester.py -d example.com --deep --whois --services --output resultado
```
Emails | WHOIS | Stack tecnológica | LinkedIn/GitHub/Twitter | SPF/DMARC | Serviços expostos

### SSL/TLS Analyzer
```bash
python3 ssl_analyzer/ssl_analyzer.py -t example.com --full --output relatorio
```
Certificado (validade, SANs, fingerprint) | TLS 1.0-1.3 | Cipher suites | HSTS | Heartbleed

### Subdomain Takeover Checker
```bash
python3 subdomain_takeover/subdomain_takeover.py -d example.com --wordlist subs.txt --output resultado
```
CNAMEs dangling → GitHub Pages, AWS S3, Heroku, Azure, Netlify, Fastly, Shopify e mais 24 serviços

## ✅ Melhorias

| Ferramenta | Novidades |
|-----------|-----------|
| Port Scanner | OS detection (TTL), UDP scan, service version, `--format all` |
| DNS Recon | SPF/DMARC/DKIM analysis, CAA records, DNSSEC hints |
| Hash Cracker | NTLM, bcrypt verify, scrypt, identificação melhorada |
| Password Cracker | NTLM, Hybrid prefix+suffix, variações automáticas, JSON output |

## 📊 Output Multi-Formato

```bash
--output relatorio    # Gera relatorio.txt + relatorio.json + relatorio.html
```

## ⚡ Severidades

CRITICAL 🔴 | HIGH 🔴 | MEDIUM 🟡 | LOW 🔵 | INFO ⚫

## 🛠️ Requisitos

Python 3.8+ — zero dependências externas.
Opcional: `pip install bcrypt` para verificar hashes bcrypt.
Root necessário para: ICMP (OS detect), ARP scan, packet sniffer, keylogger.
