#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║           OSINT / EMAIL HARVESTER v2                     ║
║  Emails | Metadados | WHOIS | Shodan | LinkedIn OSINT    ║
╚══════════════════════════════════════════════════════════╝
Uso:
  python3 osint_harvester.py -d example.com
  python3 osint_harvester.py -d example.com --deep --output relatorio
  python3 osint_harvester.py -d example.com --whois --breach-check
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))
from common import *

import socket, ssl, urllib.parse, re, threading, argparse, struct, random, json
from queue    import Queue
from datetime import datetime

# ─── Regex de extração ────────────────────────────────────────────────────────
EMAIL_RE    = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
PHONE_RE    = re.compile(r'(?:\+?\d[\d\s\-().]{7,}\d)')
LINKEDIN_RE = re.compile(r'linkedin\.com/(?:in|company)/([a-zA-Z0-9\-_]+)')
GITHUB_RE   = re.compile(r'github\.com/([a-zA-Z0-9\-_]+)')
TWITTER_RE  = re.compile(r'twitter\.com/([a-zA-Z0-9_]+)|x\.com/([a-zA-Z0-9_]+)')
IP_RE       = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# ─── Padrões de tecnologia por header/HTML ────────────────────────────────────
TECH_SIGNATURES = [
    (re.compile(r'WordPress/([0-9.]+)', re.I), "WordPress"),
    (re.compile(r'wp-content|wp-includes',  re.I), "WordPress"),
    (re.compile(r'Joomla',                  re.I), "Joomla"),
    (re.compile(r'Drupal',                  re.I), "Drupal"),
    (re.compile(r'Laravel',                 re.I), "Laravel"),
    (re.compile(r'Django',                  re.I), "Django"),
    (re.compile(r'Rails',                   re.I), "Ruby on Rails"),
    (re.compile(r'ASP\.NET',               re.I), "ASP.NET"),
    (re.compile(r'X-Powered-By:\s*PHP',    re.I), "PHP"),
    (re.compile(r'shopify',                re.I), "Shopify"),
    (re.compile(r'wix\.com',               re.I), "Wix"),
    (re.compile(r'squarespace',            re.I), "Squarespace"),
    (re.compile(r'cloudflare',             re.I), "Cloudflare"),
    (re.compile(r'react|__NEXT_DATA__',    re.I), "React/Next.js"),
    (re.compile(r'vue\.js|vuex',           re.I), "Vue.js"),
    (re.compile(r'angular',                re.I), "Angular"),
    (re.compile(r'jQuery/([0-9.]+)',       re.I), "jQuery"),
    (re.compile(r'bootstrap',             re.I), "Bootstrap"),
    (re.compile(r'google-analytics|gtag', re.I), "Google Analytics"),
]

# ─── HTTP simples ─────────────────────────────────────────────────────────────
def http_get(url, timeout=8):
    try:
        if not url.startswith("http"):
            url = "http://" + url
        p = urllib.parse.urlparse(url)
        scheme = p.scheme
        host   = p.hostname
        port   = p.port or (443 if scheme == "https" else 80)
        path   = (p.path or "/") + ("?" + p.query if p.query else "")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((socket.gethostbyname(host), port))
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)

        req = (f"GET {path} HTTP/1.1\r\n"
               f"Host: {host}\r\n"
               f"User-Agent: Mozilla/5.0 (compatible; MSIE 9.0)\r\n"
               f"Accept: */*\r\nConnection: close\r\n\r\n")
        s.send(req.encode())

        raw = b""
        while True:
            chunk = s.recv(8192)
            if not chunk: break
            raw += chunk
            if len(raw) > 300_000: break
        s.close()

        if b"\r\n\r\n" not in raw:
            return None, {}
        hpart, body = raw.split(b"\r\n\r\n", 1)
        hdrs = {}
        for line in hpart.decode("utf-8", errors="ignore").split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                hdrs[k.strip().lower()] = v.strip()
        return body.decode("utf-8", errors="ignore"), hdrs
    except:
        return None, {}


# ─── WHOIS raw ────────────────────────────────────────────────────────────────
def whois_query(domain, server="whois.iana.org", port=43):
    results = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(8)
        s.connect((server, port))
        s.send((domain + "\r\n").encode())
        raw = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            raw += chunk
        s.close()
        text = raw.decode("utf-8", errors="ignore")

        # Tenta referral server do IANA
        refer_m = re.search(r'refer:\s*(\S+)', text, re.IGNORECASE)
        if refer_m and server == "whois.iana.org":
            return whois_query(domain, refer_m.group(1))

        # Parse campos comuns
        for field in ["Registrar","Registrant","Creation Date","Updated Date",
                      "Expiry Date","Name Server","DNSSEC","Registry Domain ID",
                      "Registrar WHOIS Server","Registrant Organization",
                      "Registrant Country","Admin Email","Tech Email"]:
            m = re.search(rf'{re.escape(field)}:\s*(.+)', text, re.IGNORECASE)
            if m:
                results[field] = m.group(1).strip()

        results["_raw"] = text[:3000]
        return results
    except Exception as e:
        return {"error": str(e)}


# ─── DNS OSINT ────────────────────────────────────────────────────────────────
def dns_records(domain, nameserver="8.8.8.8"):
    """Consulta registros DNS relevantes para OSINT."""
    import struct, random

    def build_query(name, qtype):
        txid = random.randint(0, 65535)
        hdr  = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        qname = b""
        for label in name.split("."):
            enc = label.encode()
            qname += struct.pack("B", len(enc)) + enc
        qname += b"\x00"
        return txid, hdr + qname + struct.pack("!HH", qtype, 1)

    def send_query(name, qtype):
        try:
            _, pkt = build_query(name, qtype)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            s.sendto(pkt, (nameserver, 53))
            resp, _ = s.recvfrom(4096)
            s.close()
            return resp.decode("utf-8", errors="ignore") if resp else ""
        except:
            return ""

    results = {}

    # A / AAAA / MX / TXT via getaddrinfo / gethostbyname
    try:
        results["A"] = socket.gethostbyname(domain)
    except:
        results["A"] = None

    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET6)
        results["AAAA"] = infos[0][4][0] if infos else None
    except:
        results["AAAA"] = None

    # SPF / DMARC / DKIM via TXT (usando raw UDP)
    for check_domain, label in [
        (domain,                 "TXT"),
        (f"_dmarc.{domain}",     "DMARC"),
        (f"_domainkey.{domain}", "DKIM"),
    ]:
        resp = send_query(check_domain, 16)  # TXT=16
        results[label] = resp[50:200] if resp else ""

    # MX
    resp = send_query(domain, 15)
    results["MX_raw"] = bool(resp and len(resp) > 30)

    # NS
    try:
        ns_list = []
        resp = send_query(domain, 2)  # NS=2
        results["NS_found"] = bool(resp and len(resp) > 30)
    except:
        pass

    return results


# ─── Detecção de tecnologias ──────────────────────────────────────────────────
def detect_technologies(html_body, headers):
    detected = set()
    combined = html_body + "\n".join(f"{k}: {v}" for k,v in headers.items())
    for pattern, name in TECH_SIGNATURES:
        if pattern.search(combined):
            detected.add(name)
    # Server header
    if "server" in headers:
        detected.add(f"Server: {headers['server']}")
    if "x-powered-by" in headers:
        detected.add(f"Powered-By: {headers['x-powered-by']}")
    return detected


# ─── Extrai emails de múltiplas fontes ───────────────────────────────────────
def harvest_emails(domain, deep=False):
    emails_found = set()
    sources      = []

    # 1. Página principal
    for scheme in ["https", "http"]:
        body, hdrs = http_get(f"{scheme}://{domain}")
        if body:
            found = EMAIL_RE.findall(body)
            emails_found.update(found)
            sources.append(f"{scheme}://{domain} (homepage)")
            break

    # 2. Páginas comuns
    pages_to_check = ["/contact", "/about", "/team", "/about-us",
                       "/contact-us", "/staff", "/people", "/imprint"]
    if deep:
        pages_to_check += ["/careers", "/jobs", "/support", "/help",
                            "/company", "/press", "/media", "/privacy"]

    for path in pages_to_check:
        body, _ = http_get(f"https://{domain}{path}")
        if body:
            found = EMAIL_RE.findall(body)
            if found:
                emails_found.update(found)
                sources.append(f"https://{domain}{path}")

    # 3. robots.txt e sitemap
    for special in ["/robots.txt", "/sitemap.xml"]:
        body, _ = http_get(f"https://{domain}{special}")
        if body:
            found = EMAIL_RE.findall(body)
            emails_found.update(found)

    # 4. Filtrar emails do próprio domínio vs externos
    own     = {e for e in emails_found if domain in e}
    foreign = emails_found - own

    return list(own), list(foreign), sources


# ─── Extrai social media handles ─────────────────────────────────────────────
def harvest_social(domain):
    social = {"linkedin": set(), "github": set(), "twitter": set()}
    body, _ = http_get(f"https://{domain}")
    if not body:
        return social

    for m in LINKEDIN_RE.finditer(body):
        social["linkedin"].add(m.group(1))
    for m in GITHUB_RE.finditer(body):
        social["github"].add(m.group(1))
    for m in TWITTER_RE.finditer(body):
        handle = m.group(1) or m.group(2)
        if handle and handle.lower() not in ("share","intent","home"):
            social["twitter"].add(handle)

    return {k: list(v) for k,v in social.items()}


# ─── Shodan-like banner check (sem API) ──────────────────────────────────────
def check_exposed_services(ip, reporter):
    """Verifica serviços comuns que não deveriam estar expostos."""
    SENSITIVE_PORTS = {
        21:  ("FTP", "HIGH"),
        23:  ("Telnet", "CRITICAL"),
        445: ("SMB", "HIGH"),
        3306:("MySQL", "HIGH"),
        5432:("PostgreSQL", "HIGH"),
        6379:("Redis", "CRITICAL"),
        27017:("MongoDB", "CRITICAL"),
        9200:("Elasticsearch", "CRITICAL"),
        11211:("Memcached", "HIGH"),
        2375:("Docker API", "CRITICAL"),
        5000:("Possível API/Flask", "MEDIUM"),
        8080:("HTTP Alt", "LOW"),
        8443:("HTTPS Alt", "LOW"),
    }

    print(f"\n  {B}[*]{RST} Verificando serviços expostos em {ip}...")
    exposed = []
    for port, (svc, sev) in SENSITIVE_PORTS.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            r = s.connect_ex((ip, port))
            s.close()
            if r == 0:
                exposed.append((port, svc, sev))
                reporter.add("Exposure", sev, f"Serviço exposto: {svc} (:{port})",
                             f"IP: {ip}:{port} — serviço não deveria estar acessível externamente",
                             {"ip": ip, "port": port, "service": svc})
                print_finding(sev, "Exposure", f"{svc} acessível em :{port}")
        except:
            pass
    return exposed


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    print_header(
        "OSINT / EMAIL HARVESTER v2",
        "Emails | WHOIS | DNS | Tecnologias | Redes Sociais | Serviços Expostos",
        color=M
    )

    parser = argparse.ArgumentParser(description="OSINT Harvester — Python puro")
    parser.add_argument("-d","--domain",     required=True, help="Domínio alvo (ex: example.com)")
    parser.add_argument("--deep",            action="store_true", help="Crawl mais profundo")
    parser.add_argument("--whois",           action="store_true", help="Consultar WHOIS")
    parser.add_argument("--services",        action="store_true", help="Verificar serviços expostos")
    parser.add_argument("--output",          default=None, help="Base do arquivo de saída")
    args = parser.parse_args()

    domain   = args.domain.lower().strip().removeprefix("http://").removeprefix("https://").split("/")[0]
    reporter = Reporter("OSINT Harvester", domain)

    print(f"  {B}[*]{RST} Domínio : {W}{domain}{RST}")
    print(f"  {B}[*]{RST} Início  : {datetime.now().strftime('%H:%M:%S')}\n")
    print(f"  {C}{'─'*60}{RST}")

    # ── 1. Resolução DNS ──
    print(f"  {Y}[DNS]{RST} Resolvendo registros...")
    ip = resolve(domain)
    if ip:
        reporter.set_meta("IP", ip)
        print(f"  {G}[A]{RST} {domain} → {ip}")
        reporter.add("DNS", "INFO", f"Registro A: {ip}", f"{domain} → {ip}", {"ip": ip})
    else:
        print(f"  {R}[!]{RST} Não foi possível resolver {domain}")

    dns_info = dns_records(domain)
    if dns_info.get("AAAA"):
        print(f"  {G}[AAAA]{RST} {dns_info['AAAA']}")
        reporter.add("DNS", "INFO", f"IPv6: {dns_info['AAAA']}")

    # SPF / DMARC
    for key, label in [("TXT","SPF/TXT"), ("DMARC","DMARC")]:
        raw = dns_info.get(key,"")
        has_spf   = "v=spf1" in raw
        has_dmarc = "v=DMARC1" in raw
        if key == "TXT":
            if not has_spf:
                reporter.add("Email Security", "MEDIUM", "SPF ausente",
                             "Sem registro SPF — risco de email spoofing")
                print_finding("MEDIUM", "Email Sec", "SPF ausente — risco de spoofing")
            else:
                reporter.add("Email Security", "INFO", "SPF configurado")
                print(f"  {G}[SPF]{RST} Configurado")
        if key == "DMARC" and not has_dmarc:
            reporter.add("Email Security", "MEDIUM", "DMARC ausente",
                         "Sem política DMARC — emails falsificados podem ser entregues")
            print_finding("MEDIUM", "Email Sec", "DMARC ausente")

    # ── 2. WHOIS ──
    if args.whois:
        print(f"\n  {Y}[WHOIS]{RST} Consultando...")
        wdata = whois_query(domain)
        if "error" not in wdata:
            for field, value in wdata.items():
                if field == "_raw": continue
                print(f"  {C}{field:<35}{RST} {DIM}{value[:80]}{RST}")
                reporter.add("WHOIS", "INFO", field, value)
                reporter.set_meta(field, value[:120])
        else:
            print(f"  {R}[!]{RST} WHOIS falhou: {wdata.get('error')}")

    # ── 3. Tecnologias ──
    print(f"\n  {Y}[TECH]{RST} Detectando tecnologias...")
    body, hdrs = http_get(f"https://{domain}")
    if not body:
        body, hdrs = http_get(f"http://{domain}")
    if body:
        techs = detect_technologies(body, hdrs)
        if techs:
            for t in sorted(techs):
                print(f"  {G}[TECH]{RST} {t}")
                reporter.add("Technology", "INFO", t)
            reporter.set_meta("Tecnologias", ", ".join(sorted(techs)))
        else:
            print(f"  {DIM}Nenhuma tecnologia identificada{RST}")

    # ── 4. Harvest emails ──
    print(f"\n  {Y}[EMAILS]{RST} Coletando emails ({'deep' if args.deep else 'padrão'})...")
    own_emails, foreign_emails, sources = harvest_emails(domain, deep=args.deep)

    if own_emails:
        print(f"  {G}[+] {len(own_emails)} email(s) do domínio:{RST}")
        for e in sorted(set(own_emails)):
            print(f"      {W}{e}{RST}")
            reporter.add("Email", "MEDIUM", f"Email exposto: {e}",
                         f"Domínio próprio — potencial alvo de phishing/spam",
                         {"email": e, "type": "own"})
    else:
        print(f"  {DIM}Nenhum email do domínio encontrado{RST}")

    if foreign_emails:
        print(f"  {Y}[+] {len(foreign_emails)} email(s) externos:{RST}")
        for e in sorted(set(foreign_emails))[:10]:
            print(f"      {DIM}{e}{RST}")
            reporter.add("Email", "INFO", f"Email externo: {e}", "", {"email": e, "type": "foreign"})

    reporter.set_meta("Emails próprios", len(own_emails))
    reporter.set_meta("Emails externos", len(foreign_emails))

    # ── 5. Redes sociais ──
    print(f"\n  {Y}[SOCIAL]{RST} Buscando referências a redes sociais...")
    social = harvest_social(domain)
    for platform, handles in social.items():
        for h in handles:
            print(f"  {G}[{platform.upper()}]{RST} {h}")
            reporter.add("Social Media", "INFO", f"{platform}: {h}",
                         f"Handle encontrado: {h}")
    if not any(social.values()):
        print(f"  {DIM}Nenhuma referência a redes sociais encontrada{RST}")

    # ── 6. Serviços expostos ──
    if args.services and ip:
        check_exposed_services(ip, reporter)

    # ── Resumo ──
    sev_counts = {}
    for f in reporter.findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    print(f"\n{C}{'═'*62}{RST}")
    print(f"{BOLD}  RESUMO OSINT — {domain}{RST}")
    print(f"{C}{'═'*62}{RST}")
    print(f"  IP          : {ip or 'N/A'}")
    print(f"  Emails      : {len(own_emails)} próprios, {len(foreign_emails)} externos")
    print(f"  Findings    : {len(reporter.findings)}")
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        cnt = sev_counts.get(sev, 0)
        if cnt:
            sc = severity_color(sev)
            print(f"  {sc}{sev:<10}{RST} {cnt}")

    if args.output:
        reporter.save_all(args.output)
    else:
        print(f"\n  {DIM}Use --output <base> para salvar TXT/JSON/HTML{RST}")

if __name__ == "__main__":
    main()
