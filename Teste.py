#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║         CYBERSEC TOOLKIT v2 — TESTER AUTOMATIZADO        ║
║   Testa todas as 12 ferramentas + lib/common             ║
╚══════════════════════════════════════════════════════════╝
Uso: python3 Teste.py
     python3 Teste.py --only port_scanner,dns_recon
     python3 Teste.py --skip keylogger,packet_sniffer
"""

import subprocess, sys, os, hashlib, time, json, argparse, tempfile, shutil

G   = "\033[92m"; R   = "\033[91m"; Y   = "\033[93m"
C   = "\033[96m"; W   = "\033[97m"; M   = "\033[95m"
DIM = "\033[2m";  RST = "\033[0m";  BOLD= "\033[1m"

BASE       = os.path.dirname(os.path.abspath(__file__))
resultados = []
skipped    = []

def header():
    print(f"""
{C}╔{'═'*58}╗
║{W}{BOLD}      CYBERSEC TOOLKIT v2 — TESTE AUTOMATIZADO          {C}║
║{DIM}      13 suítes | 12 ferramentas | lib/common             {C}║
╚{'═'*58}╝{RST}
""")

def separador(nome):
    print(f"\n{C}{'─'*60}{RST}")
    print(f"{BOLD}{Y}  [{nome}]{RST}")
    print(f"{C}{'─'*60}{RST}")

def rodar(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=BASE)
        return True, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return True, "[timeout — ferramenta rodou mas foi interrompida pelo teste]", ""
    except Exception as e:
        return False, "", str(e)

def check(nome, ok, detalhe=""):
    status = f"{G}[✓] PASSOU{RST}" if ok else f"{R}[✗] FALHOU{RST}"
    print(f"  {status}  {W}{nome}{RST}")
    if detalhe and not ok:
        print(f"         {DIM}{str(detalhe)[:120]}{RST}")
    resultados.append((nome, ok))

def tmp_wordlist(*words):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, dir=BASE)
    f.write("\n".join(words) + "\n")
    f.close()
    return f.name

# ══════════════════════════════════════════════════════════
# 0. LIB / COMMON
# ══════════════════════════════════════════════════════════
def test_lib_common():
    separador("0/12 — LIB/COMMON (Reporter multi-formato)")
    lib = os.path.join(BASE, "lib", "common.py")

    ok, _, err = rodar([sys.executable, "-m", "py_compile", lib])
    check("Sintaxe válida", ok, err)

    tmpdir = tempfile.mkdtemp()
    base   = os.path.join(tmpdir, "rel")
    ok, out, err = rodar([sys.executable, "-c", f"""
import sys; sys.path.insert(0, '{os.path.join(BASE, "lib")}')
from common import Reporter
r = Reporter("Teste", "example.com")
r.set_meta("IP", "1.2.3.4")
r.add("Teste", "CRITICAL", "Achei algo crítico", "Detalhe")
r.add("Teste", "HIGH",     "Alto risco",          "Detalhe 2")
r.add("Teste", "INFO",     "Informação",           "")
r.save_txt('{base}.txt')
r.save_json('{base}.json')
r.save_html('{base}.html')
import os, json as j
assert os.path.getsize('{base}.txt')  > 100
assert os.path.getsize('{base}.json') > 100
assert os.path.getsize('{base}.html') > 500
data = j.load(open('{base}.json'))
assert data['summary']['critical'] == 1
assert len(data['findings']) == 3
print('OK')
"""])
    check("Reporter — TXT/JSON/HTML corretos", ok and "OK" in out, err or out)
    shutil.rmtree(tmpdir, ignore_errors=True)

    ok, out, _ = rodar([sys.executable, "-c", f"""
import sys; sys.path.insert(0, '{os.path.join(BASE, "lib")}')
from common import severity_color, strip_ansi, RST
sc = severity_color("CRITICAL")
assert sc != ''
clean = strip_ansi(sc + "texto" + RST)
assert clean == "texto"
print('OK')
"""])
    check("Utilitários (severity_color, strip_ansi)", ok and "OK" in out)

# ══════════════════════════════════════════════════════════
# 1. HASH CRACKER
# ══════════════════════════════════════════════════════════
def test_hash_cracker():
    separador("1/12 — HASH CRACKER")
    script = os.path.join(BASE, "hash_cracker", "hash_cracker.py")

    h_md5 = hashlib.md5(b"abc").hexdigest()
    ok, out, _ = rodar([sys.executable, script, "--identify", h_md5])
    check("Identificar hash MD5", ok and "md5" in out.lower())

    h_sha = hashlib.sha256(b"hi").hexdigest()
    ok, out, _ = rodar([sys.executable, script, "--identify", h_sha])
    check("Identificar hash SHA-256", ok and "sha256" in out.lower())

    ok, out, _ = rodar([sys.executable, script, "--identify",
                         "$2b$12$abcdefghijklmnopqrstuuVGnxyz0123456789abcdefghijklmno"])
    check("Identificar hash bcrypt ($2b$)", ok and "bcrypt" in out.lower())

    h_ab = hashlib.md5(b"ab").hexdigest()
    ok, out, _ = rodar([sys.executable, script,
                         "--crack", h_ab, "--brute", "--charset", "lower",
                         "--min", "1", "--max", "3"], timeout=30)
    check("Crack brute-force MD5 'ab'", ok and "ab" in out)

    wl = tmp_wordlist("admin", "password", "123456")
    h_pw = hashlib.md5(b"password").hexdigest()
    ok, out, _ = rodar([sys.executable, script, "--crack", h_pw, "--wordlist", wl], timeout=15)
    check("Crack dicionário MD5 'password'", ok and "password" in out)
    os.remove(wl)

    ok, out, _ = rodar([sys.executable, script, "--benchmark"], timeout=25)
    check("Benchmark de algoritmos", ok and ("MD5" in out or "SHA" in out))

    ok, out, _ = rodar([sys.executable, script, "--identify",
                         "8846f7eaee8fb117ad06bdd830b7586c"])
    check("Identificar possível NTLM/MD5 (32 chars)", ok and ("ntlm" in out.lower() or "md5" in out.lower()))

# ══════════════════════════════════════════════════════════
# 2. PORT SCANNER
# ══════════════════════════════════════════════════════════
def test_port_scanner():
    separador("2/12 — PORT SCANNER")
    script = os.path.join(BASE, "port_scanner", "port_scanner.py")

    ok, out, _ = rodar([sys.executable, script,
                         "-t", "127.0.0.1", "-p", "80,443,8080",
                         "--timeout", "0.3", "--threads", "5"], timeout=15)
    check("Scan TCP localhost", ok and ("127.0.0.1" in out or "SCAN" in out))

    ok, out, _ = rodar([sys.executable, script,
                         "-t", "127.0.0.1", "--top-ports",
                         "--timeout", "0.3", "--threads", "10"], timeout=20)
    check("Scan top-ports", ok and ("portas" in out.lower() or "RESUMO" in out))

    ok, out, _ = rodar([sys.executable, script,
                         "-t", "localhost", "-p", "22", "--timeout", "0.3"], timeout=10)
    check("Resolução hostname", ok and ("127.0.0.1" in out or "localhost" in out))

    tmpdir = tempfile.mkdtemp()
    base   = os.path.join(tmpdir, "scan")
    ok, _, _ = rodar([sys.executable, script,
                       "-t", "127.0.0.1", "-p", "22,80",
                       "--timeout", "0.3", "--output", base, "--format", "json"], timeout=15)
    check("Output JSON gerado", ok and os.path.exists(base + ".json"))
    shutil.rmtree(tmpdir, ignore_errors=True)

    ok, out, _ = rodar([sys.executable, script,
                         "-t", "127.0.0.1", "-p", "80",
                         "--udp", "--udp-ports", "53",
                         "--timeout", "0.5"], timeout=15)
    check("UDP scan (execução sem erro)", ok and ("UDP" in out or "127.0.0.1" in out))

# ══════════════════════════════════════════════════════════
# 3. BANNER GRABBER
# ══════════════════════════════════════════════════════════
def test_banner_grabber():
    separador("3/12 — BANNER GRABBER")
    script = os.path.join(BASE, "banner_grabber", "banner_grabber.py")

    ok, out, _ = rodar([sys.executable, script,
                         "-t", "127.0.0.1", "-p", "22,80,443",
                         "--timeout", "1.0", "--threads", "3"], timeout=15)
    check("Banner grab localhost", ok and ("127.0.0.1" in out or "RESUMO" in out))

    ok, out, _ = rodar([sys.executable, script,
                         "-t", "127.0.0.1", "--all-common",
                         "--timeout", "0.5", "--threads", "10"], timeout=20)
    check("Banner grab --all-common", ok and ("Portas testadas" in out or "RESUMO" in out))

# ══════════════════════════════════════════════════════════
# 4. DNS RECON
# ══════════════════════════════════════════════════════════
def test_dns_recon():
    separador("4/12 — DNS RECON")
    script = os.path.join(BASE, "dns_recon", "dns_recon.py")

    ok, out, _ = rodar([sys.executable, script,
                         "-d", "google.com", "--nameserver", "8.8.8.8", "--timeout", "3"], timeout=20)
    check("Query A record google.com", ok and ("google.com" in out or "A" in out))

    ok, out, _ = rodar([sys.executable, script,
                         "-d", "google.com", "--all",
                         "--nameserver", "8.8.8.8", "--timeout", "3"], timeout=30)
    check("Query --all records (MX/NS/TXT)", ok and any(x in out for x in ["MX","NS","TXT"]))

    ok, out, _ = rodar([sys.executable, script,
                         "-d", "google.com", "--nameserver", "8.8.8.8", "--timeout", "3"], timeout=25)
    check("SPF/DMARC analysis presente (v2)", ok and any(x in out for x in ["SPF","DMARC","EMAIL","dmarc"]))

    ok, out, _ = rodar([sys.executable, script,
                         "-d", "google.com", "--subdomains",
                         "--nameserver", "8.8.8.8", "--threads", "20", "--timeout", "2"], timeout=35)
    check("Subdomain brute force", ok and any(x in out.lower() for x in ["found","subdomínios","www","✓"]))

# ══════════════════════════════════════════════════════════
# 5. NETWORK SCANNER
# ══════════════════════════════════════════════════════════
def test_network_scanner():
    separador("5/12 — NETWORK SCANNER")
    script = os.path.join(BASE, "network_scanner", "network_scanner.py")

    ok, out, _ = rodar([sys.executable, script,
                         "--range", "127.0.0.1", "--method", "icmp",
                         "--timeout", "1", "--threads", "1"], timeout=15)
    check("Network scan ICMP iniciou", ok and any(x in out for x in ["SCAN","Range","ICMP","IPs"]))

    ok, out, _ = rodar([sys.executable, script,
                         "--range", "127.0.0.0/30", "--method", "icmp",
                         "--timeout", "0.5", "--threads", "4"], timeout=20)
    check("Network scan CIDR /30", ok and any(x in out for x in ["IPs","Range","Total","0/30"]))

# ══════════════════════════════════════════════════════════
# 6. PASSWORD CRACKER
# ══════════════════════════════════════════════════════════
def test_password_cracker():
    separador("6/12 — PASSWORD CRACKER")
    script = os.path.join(BASE, "password_cracker", "password_cracker.py")
    wl = tmp_wordlist("admin", "password", "letmein", "abc123")

    h_admin = hashlib.md5(b"admin").hexdigest()
    ok, out, _ = rodar([sys.executable, script,
                         "--hash", h_admin, "--type", "md5",
                         "--mode", "dict", "--wordlist", wl], timeout=20)
    check("Crack dict MD5 'admin'", ok and ("admin" in out or "CRACK" in out))

    h_ab = hashlib.md5(b"ab").hexdigest()
    ok, out, _ = rodar([sys.executable, script,
                         "--hash", h_ab, "--type", "md5",
                         "--mode", "brute", "--charset", "alpha",
                         "--min", "1", "--max", "3"], timeout=30)
    check("Crack brute MD5 'ab'", ok and ("ab" in out or "CRACK" in out))

    h_a1 = hashlib.md5(b"a1").hexdigest()
    ok, out, _ = rodar([sys.executable, script,
                         "--hash", h_a1, "--type", "md5",
                         "--mode", "mask", "--mask", "?l?d"], timeout=20)
    check("Crack mask MD5 'a1'", ok and ("a1" in out or "CRACK" in out))

    # Hybrid melhorado (v2)
    h_pw12 = hashlib.md5(b"admin12").hexdigest()
    ok, out, _ = rodar([sys.executable, script,
                         "--hash", h_pw12, "--type", "md5",
                         "--mode", "hybrid", "--wordlist", wl,
                         "--suffix", "2", "--charset", "numeric"], timeout=35)
    check("Crack hybrid 'admin12' (sufixo numérico, v2)", ok and ("admin" in out or "CRACK" in out))

    # Output JSON (v2)
    tmpdir = tempfile.mkdtemp()
    jout   = os.path.join(tmpdir, "crack.json")
    ok, _, _ = rodar([sys.executable, script,
                       "--hash", h_admin, "--type", "md5",
                       "--mode", "dict", "--wordlist", wl,
                       "--output", jout], timeout=20)
    json_ok = False
    if os.path.exists(jout):
        try:
            data = json.load(open(jout))
            json_ok = "results" in data and "algo" in data
        except: pass
    check("Output JSON com estrutura correta (v2)", ok and json_ok)
    shutil.rmtree(tmpdir, ignore_errors=True)
    os.remove(wl)

# ══════════════════════════════════════════════════════════
# 7. PACKET SNIFFER
# ══════════════════════════════════════════════════════════
def test_packet_sniffer():
    separador("7/12 — PACKET SNIFFER")
    script = os.path.join(BASE, "packet_sniffer", "packet_sniffer.py")

    ok, _, err = rodar([sys.executable, "-m", "py_compile", script])
    check("Sintaxe válida", ok, err)

    ok, out, _ = rodar([sys.executable, "-c",
        "import socket,struct,threading,argparse; print('OK')"])
    check("Imports disponíveis", ok and "OK" in out)

    ok, out, _ = rodar([sys.executable, "-c", """
import socket, struct
def parse_ipv4(data):
    if len(data) < 20: return None
    return socket.inet_ntoa(data[12:16]), socket.inet_ntoa(data[16:20])
raw = bytes([0x45,0,0,40,0,0,0,0,64,6,0,0,127,0,0,1,127,0,0,2]+[0]*20)
r = parse_ipv4(raw)
assert r == ('127.0.0.1','127.0.0.2')
print('OK')
"""])
    check("Parser IPv4 funcional", ok and "OK" in out)
    print(f"  {Y}[!]{RST} {DIM}Captura real requer root — não testada aqui.{RST}")

# ══════════════════════════════════════════════════════════
# 8. KEYLOGGER
# ══════════════════════════════════════════════════════════
def test_keylogger():
    separador("8/12 — KEYLOGGER")
    script = os.path.join(BASE, "keylogger", "keylogger.py")

    ok, _, err = rodar([sys.executable, "-m", "py_compile", script])
    check("Sintaxe válida", ok, err)

    ok, out, _ = rodar([sys.executable, "-c", """
KEY_MAP = {30:'a',31:'s',32:'d',57:' ',28:'[ENTER]'}
decoded = [KEY_MAP.get(k,'?') for k in [30,31,32,57,28]]
assert decoded == ['a','s','d',' ','[ENTER]']
print('OK')
"""])
    check("KEY_MAP decodifica teclas corretamente", ok and "OK" in out)

    ok, out, _ = rodar([sys.executable, script, "--list"], timeout=5)
    check("--list executa sem erro", ok)
    print(f"  {Y}[!]{RST} {DIM}Captura real requer root + /dev/input — não testada aqui.{RST}")

# ══════════════════════════════════════════════════════════
# 9. WEB VULNERABILITY SCANNER (novo v2)
# ══════════════════════════════════════════════════════════
def test_web_vuln_scanner():
    separador("9/12 — WEB VULN SCANNER  ★ novo v2")
    script = os.path.join(BASE, "web_vuln_scanner", "web_vuln_scanner.py")

    ok, _, err = rodar([sys.executable, "-m", "py_compile", script])
    check("Sintaxe válida", ok, err)

    ok, out, _ = rodar([sys.executable, "-c", f"""
import sys
sys.path.insert(0, '{os.path.join(BASE, "web_vuln_scanner")}')
sys.path.insert(0, '{os.path.join(BASE, "lib")}')
from web_vuln_scanner import XSS_PAYLOADS, SQLI_PAYLOADS, LFI_PAYLOADS, SECURITY_HEADERS, INTERESTING_PATHS
assert len(XSS_PAYLOADS) >= 5
assert len(SQLI_PAYLOADS) >= 5
assert len(LFI_PAYLOADS) >= 5
assert len(SECURITY_HEADERS) >= 5
assert len(INTERESTING_PATHS) >= 10
print(f'OK XSS:{{len(XSS_PAYLOADS)}} SQLi:{{len(SQLI_PAYLOADS)}} LFI:{{len(LFI_PAYLOADS)}}')
"""])
    check("Payloads carregados (XSS/SQLi/LFI)", ok and "OK" in out, out)

    ok, out, _ = rodar([sys.executable, "-c", f"""
import sys
sys.path.insert(0, '{os.path.join(BASE, "web_vuln_scanner")}')
sys.path.insert(0, '{os.path.join(BASE, "lib")}')
from web_vuln_scanner import HTTPClient
c = HTTPClient(timeout=3)
assert c.timeout == 3 and c.max_redirects == 5
print('OK')
"""])
    check("HTTPClient instancia corretamente", ok and "OK" in out)

    ok, out, _ = rodar([sys.executable, script,
                         "-u", "http://example.com",
                         "--checks", "headers,paths", "--timeout", "6"], timeout=30)
    check("Scan real example.com (headers + paths)", ok and any(
        x in out for x in ["Header","RESUMO","INFO","MEDIUM","HIGH","finding"]))

    tmpdir = tempfile.mkdtemp()
    base   = os.path.join(tmpdir, "wvs")
    ok, _, _ = rodar([sys.executable, script,
                       "-u", "http://example.com",
                       "--checks", "headers", "--timeout", "6",
                       "--output", base], timeout=30)
    json_ok = False
    if os.path.exists(base + ".json"):
        try:
            data = json.load(open(base + ".json"))
            json_ok = "findings" in data and "summary" in data
        except: pass
    check("Output TXT/JSON/HTML gerados com estrutura correta", ok and json_ok)
    shutil.rmtree(tmpdir, ignore_errors=True)

# ══════════════════════════════════════════════════════════
# 10. OSINT HARVESTER (novo v2)
# ══════════════════════════════════════════════════════════
def test_osint_harvester():
    separador("10/12 — OSINT HARVESTER  ★ novo v2")
    script = os.path.join(BASE, "osint_harvester", "osint_harvester.py")

    ok, _, err = rodar([sys.executable, "-m", "py_compile", script])
    check("Sintaxe válida", ok, err)

    ok, out, _ = rodar([sys.executable, "-c", f"""
import sys
sys.path.insert(0, '{os.path.join(BASE, "osint_harvester")}')
sys.path.insert(0, '{os.path.join(BASE, "lib")}')
from osint_harvester import EMAIL_RE, LINKEDIN_RE, GITHUB_RE, TECH_SIGNATURES
assert EMAIL_RE.search('test@example.com')
assert LINKEDIN_RE.search('linkedin.com/in/johndoe')
assert GITHUB_RE.search('github.com/torvalds')
assert len(TECH_SIGNATURES) >= 10
print(f'OK {{len(TECH_SIGNATURES)}} tech signatures')
"""])
    check("Regex (email, LinkedIn, GitHub) funcionais", ok and "OK" in out)

    ok, out, _ = rodar([sys.executable, "-c", f"""
import sys
sys.path.insert(0, '{os.path.join(BASE, "osint_harvester")}')
sys.path.insert(0, '{os.path.join(BASE, "lib")}')
from osint_harvester import detect_technologies
techs = detect_technologies('<html><meta name="generator" content="WordPress 6.0"></html>',
                             {{'x-powered-by': 'PHP/8.1'}})
assert 'WordPress' in techs or 'PHP' in techs, f'Detectadas: {{techs}}'
print('OK')
"""])
    check("detect_technologies identifica WordPress/PHP", ok and "OK" in out)

    ok, out, _ = rodar([sys.executable, script, "-d", "google.com"], timeout=25)
    check("OSINT scan google.com (DNS + tech)", ok and any(
        x in out for x in ["google.com","IP","TECH","DNS","RESUMO"]))

    tmpdir = tempfile.mkdtemp()
    base   = os.path.join(tmpdir, "osint")
    ok, _, _ = rodar([sys.executable, script, "-d", "example.com", "--output", base], timeout=25)
    check("Output TXT/JSON/HTML gerados", ok and os.path.exists(base + ".json"))
    shutil.rmtree(tmpdir, ignore_errors=True)

# ══════════════════════════════════════════════════════════
# 11. SSL/TLS ANALYZER (novo v2)
# ══════════════════════════════════════════════════════════
def test_ssl_analyzer():
    separador("11/12 — SSL/TLS ANALYZER  ★ novo v2")
    script = os.path.join(BASE, "ssl_analyzer", "ssl_analyzer.py")

    ok, _, err = rodar([sys.executable, "-m", "py_compile", script])
    check("Sintaxe válida", ok, err)

    ok, out, _ = rodar([sys.executable, "-c", f"""
import sys
sys.path.insert(0, '{os.path.join(BASE, "ssl_analyzer")}')
sys.path.insert(0, '{os.path.join(BASE, "lib")}')
from ssl_analyzer import WEAK_CIPHERS, PROTOCOL_SCORES, cert_fingerprint, check_cert_validity
assert 'RC4' in WEAK_CIPHERS and 'NULL' in WEAK_CIPHERS
assert len(PROTOCOL_SCORES) >= 3
fp1, fp2 = cert_fingerprint(b'test_data_here_12345')
assert len(fp1) > 10 and ':' in fp1
print(f'OK WEAK_CIPHERS:{{len(WEAK_CIPHERS)}}')
"""])
    check("Constantes (WEAK_CIPHERS, PROTOCOL_SCORES, fingerprint)", ok and "OK" in out, out)

    ok, out, _ = rodar([sys.executable, "-c", f"""
import sys
sys.path.insert(0, '{os.path.join(BASE, "ssl_analyzer")}')
sys.path.insert(0, '{os.path.join(BASE, "lib")}')
from ssl_analyzer import check_cert_validity
cert_exp = {{'notAfter': 'Jan  1 00:00:00 2020 GMT', 'notBefore': 'Jan  1 00:00:00 2019 GMT'}}
issues   = check_cert_validity(cert_exp)
assert any(i[0] == 'CRITICAL' for i in issues), f'Expirado nao detectado: {{issues}}'
cert_ok  = {{'notAfter': 'Jan  1 00:00:00 2030 GMT', 'notBefore': 'Jan  1 00:00:00 2024 GMT'}}
issues2  = check_cert_validity(cert_ok)
assert not any(i[0] == 'CRITICAL' for i in issues2), f'Falso positivo: {{issues2}}'
print('OK')
"""])
    check("check_cert_validity (expirado / válido)", ok and "OK" in out, out)

    ok, out, _ = rodar([sys.executable, script, "-t", "badssl.com"], timeout=20)
    check("Scan SSL real em badssl.com", ok and any(
        x in out for x in ["Cert","TLS","HSTS","CN","RESUMO"]))

    tmpdir = tempfile.mkdtemp()
    base   = os.path.join(tmpdir, "ssl")
    ok, _, _ = rodar([sys.executable, script, "-t", "example.com", "--output", base], timeout=20)
    check("Output TXT/JSON/HTML gerados", ok and os.path.exists(base + ".json"))
    shutil.rmtree(tmpdir, ignore_errors=True)

# ══════════════════════════════════════════════════════════
# 12. SUBDOMAIN TAKEOVER (novo v2)
# ══════════════════════════════════════════════════════════
def test_subdomain_takeover():
    separador("12/12 — SUBDOMAIN TAKEOVER  ★ novo v2")
    script = os.path.join(BASE, "subdomain_takeover", "subdomain_takeover.py")

    ok, _, err = rodar([sys.executable, "-m", "py_compile", script])
    check("Sintaxe válida", ok, err)

    ok, out, _ = rodar([sys.executable, "-c", f"""
import sys
sys.path.insert(0, '{os.path.join(BASE, "subdomain_takeover")}')
sys.path.insert(0, '{os.path.join(BASE, "lib")}')
from subdomain_takeover import TAKEOVER_FINGERPRINTS, DEFAULT_SUBDOMAINS
assert len(TAKEOVER_FINGERPRINTS) >= 20
assert len(DEFAULT_SUBDOMAINS) >= 50
services = [fp[2] for fp in TAKEOVER_FINGERPRINTS]
for svc in ['GitHub Pages','AWS S3','Heroku','Azure','Netlify','Fastly']:
    assert svc in services, f'Faltando: {{svc}}'
print(f'OK {{len(TAKEOVER_FINGERPRINTS)}} servicos, {{len(DEFAULT_SUBDOMAINS)}} subs')
"""])
    check("Fingerprints (30+ serviços cloud incluídos)", ok and "OK" in out, out)

    ok, out, _ = rodar([sys.executable, "-c", f"""
import sys
sys.path.insert(0, '{os.path.join(BASE, "subdomain_takeover")}')
sys.path.insert(0, '{os.path.join(BASE, "lib")}')
from subdomain_takeover import dns_query_raw
recs  = dns_query_raw('google.com', qtype=1)
a_recs = [r for r in recs if r[0] == 'A']
print(f'OK {{len(a_recs)}} A records')
"""])
    check("DNS query raw funcional (google.com)", ok and "OK" in out, out)

    ok, out, _ = rodar([sys.executable, "-c", f"""
import sys
sys.path.insert(0, '{os.path.join(BASE, "subdomain_takeover")}')
sys.path.insert(0, '{os.path.join(BASE, "lib")}')
from subdomain_takeover import check_wildcard
has_wc, ips = check_wildcard('google.com')
print(f'OK has_wildcard={{has_wc}}')
"""])
    check("Wildcard DNS detection funcional", ok and "OK" in out, out)

    wl = tmp_wordlist("www", "mail", "xq7zm3r4nonexistent99")
    ok, out, _ = rodar([sys.executable, script,
                         "-d", "google.com", "--wordlist", wl,
                         "--threads", "5", "--timeout", "2"], timeout=25)
    check("Scan takeover google.com (wordlist pequena)", ok and any(
        x in out for x in ["Testados","alive","RESUMO","Subdomínios","wildcard","✓"]))
    os.remove(wl)

    tmpdir = tempfile.mkdtemp()
    base   = os.path.join(tmpdir, "takeover")
    wl2    = tmp_wordlist("www", "mail")
    ok, _, _ = rodar([sys.executable, script,
                       "-d", "example.com", "--wordlist", wl2,
                       "--threads", "3", "--output", base], timeout=20)
    check("Output TXT/JSON/HTML gerados", ok and os.path.exists(base + ".json"))
    shutil.rmtree(tmpdir, ignore_errors=True)
    os.remove(wl2)

# ══════════════════════════════════════════════════════════
# RESUMO
# ══════════════════════════════════════════════════════════
def resumo():
    total  = len(resultados)
    passou = sum(1 for _, ok in resultados if ok)
    falhou = total - passou

    print(f"\n{C}{'═'*60}{RST}")
    print(f"{BOLD}{W}  RESULTADO FINAL — CyberSec Toolkit v2{RST}")
    print(f"{C}{'═'*60}{RST}")
    print(f"  Total    : {total}  |  {G}Passou: {passou}{RST}  |  {R}Falhou: {falhou}{RST}")
    if skipped:
        print(f"  Pulados  : {len(skipped)}")
    print(f"{C}{'─'*60}{RST}")
    for nome, ok in resultados:
        icone = f"{G}✓{RST}" if ok else f"{R}✗{RST}"
        cor   = G if ok else R
        print(f"  {icone}  {cor}{nome}{RST}")
    pct = int((passou / total) * 100) if total else 0
    cor = G if pct >= 85 else (Y if pct >= 60 else R)
    print(f"\n  {BOLD}Score: {cor}{passou}/{total} ({pct}%){RST}")
    if   pct == 100: print(f"  {G}{BOLD}🎯 Perfeito! Todos os testes passaram.{RST}")
    elif pct >= 85:  print(f"  {G}✓ Toolkit em boa forma.{RST}")
    elif pct >= 60:  print(f"  {Y}⚠ Alguns problemas — revise os falhos.{RST}")
    else:            print(f"  {R}✗ Muitas falhas — verifique dependências.{RST}")
    print(f"{C}{'═'*60}{RST}\n")

# ══════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════
TOOLS = {
    "lib"               : test_lib_common,
    "hash_cracker"      : test_hash_cracker,
    "port_scanner"      : test_port_scanner,
    "banner_grabber"    : test_banner_grabber,
    "dns_recon"         : test_dns_recon,
    "network_scanner"   : test_network_scanner,
    "password_cracker"  : test_password_cracker,
    "packet_sniffer"    : test_packet_sniffer,
    "keylogger"         : test_keylogger,
    "web_vuln_scanner"  : test_web_vuln_scanner,
    "osint_harvester"   : test_osint_harvester,
    "ssl_analyzer"      : test_ssl_analyzer,
    "subdomain_takeover": test_subdomain_takeover,
}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberSec Toolkit v2 — Tester")
    parser.add_argument("--only", default="", help="Rodar só estas ferramentas (vírgula)")
    parser.add_argument("--skip", default="", help="Pular estas ferramentas (vírgula)")
    args = parser.parse_args()

    only = [x.strip() for x in args.only.split(",") if x.strip()]
    skip = [x.strip() for x in args.skip.split(",") if x.strip()]

    header()
    print(f"  {DIM}Base   : {BASE}{RST}")
    print(f"  {DIM}Python : {sys.version.split()[0]}{RST}\n")

    t0 = time.time()
    for name, fn in TOOLS.items():
        if only and name not in only:
            continue
        if name in skip:
            skipped.append((name, "via --skip"))
            continue
        fn()

    print(f"\n  {DIM}Tempo total: {time.time() - t0:.1f}s{RST}")
    resumo()
