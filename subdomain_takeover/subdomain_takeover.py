#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║          SUBDOMAIN TAKEOVER CHECKER v2                   ║
║  CNAME Dangling | Cloud Fingerprints | DNS Wildcards     ║
╚══════════════════════════════════════════════════════════╝
Uso:
  python3 subdomain_takeover.py -d example.com
  python3 subdomain_takeover.py -d example.com --wordlist subdomains.txt
  python3 subdomain_takeover.py -d example.com --threads 50 --output relatorio
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))
from common import *

import socket, ssl, struct, random, threading, argparse, time, urllib.parse
from queue    import Queue
from datetime import datetime

# ─── Fingerprints de serviços vulneráveis a takeover ─────────────────────────
# Fonte: EdOverflow/can-i-take-over-xyz (adaptado)
TAKEOVER_FINGERPRINTS = [
    # (cname_pattern, http_body_signature, service_name, severity)
    ("github.io",           "There isn't a GitHub Pages site here",      "GitHub Pages",    "CRITICAL"),
    ("amazonaws.com",       "NoSuchBucket",                              "AWS S3",          "CRITICAL"),
    ("s3.amazonaws.com",    "NoSuchBucket",                              "AWS S3",          "CRITICAL"),
    ("cloudfront.net",      "Bad request",                               "AWS CloudFront",  "HIGH"),
    ("heroku.com",          "No such app",                               "Heroku",          "CRITICAL"),
    ("herokuapp.com",       "No such app",                               "Heroku",          "CRITICAL"),
    ("azurewebsites.net",   "404 Web Site not found",                    "Azure",           "CRITICAL"),
    ("azurewebsites.net",   "does not exist",                            "Azure",           "CRITICAL"),
    ("trafficmanager.net",  "404 Not Found",                             "Azure Traffic Mgr","HIGH"),
    ("shopify.com",         "Sorry, this shop is currently unavailable", "Shopify",         "HIGH"),
    ("myshopify.com",       "Sorry, this shop is currently unavailable", "Shopify",         "HIGH"),
    ("fastly.net",          "Fastly error: unknown domain",              "Fastly",          "CRITICAL"),
    ("wpengine.com",        "The site you were looking for",             "WP Engine",       "HIGH"),
    ("squarespace.com",     "No Such Account",                           "Squarespace",     "HIGH"),
    ("surge.sh",            "project not found",                         "Surge.sh",        "CRITICAL"),
    ("netlify.com",         "Not Found",                                 "Netlify",         "HIGH"),
    ("netlify.app",         "Not Found",                                 "Netlify",         "HIGH"),
    ("readthedocs.io",      "unknown to Read the Docs",                  "ReadTheDocs",     "HIGH"),
    ("ghost.io",            "Domain does not exist",                     "Ghost",           "HIGH"),
    ("cargo.site",          "404",                                       "Cargo",           "MEDIUM"),
    ("tumblr.com",          "Whatever you were looking for doesn't live here", "Tumblr",   "HIGH"),
    ("webflow.io",          "The page you are looking for doesn't exist","Webflow",         "HIGH"),
    ("pantheon.io",         "The gods are wise",                         "Pantheon",        "MEDIUM"),
    ("mailchimp.com",       "Oops",                                      "Mailchimp",       "MEDIUM"),
    ("zendesk.com",         "Help Center Closed",                        "Zendesk",         "HIGH"),
    ("bitbucket.io",        "Repository not found",                      "Bitbucket",       "HIGH"),
    ("gitbook.io",          "Sign in to GitBook",                        "GitBook",         "MEDIUM"),
    ("statuspage.io",       "You are being redirected",                  "Statuspage",      "MEDIUM"),
    ("helpjuice.com",       "We could not find what you're looking for", "HelpJuice",       "MEDIUM"),
    ("freshdesk.com",       "There is no helpdesk here",                 "Freshdesk",       "MEDIUM"),
    ("smartjob.io",         "Job Board Is Unavailable",                  "SmartJob",        "MEDIUM"),
    ("launchrock.com",      "It looks like you may have taken a wrong turn", "Launchrock",  "MEDIUM"),
    ("intercom.com",        "Uh oh. That page doesn't exist.",           "Intercom",        "MEDIUM"),
]

# Subdomínios padrão para testar
DEFAULT_SUBDOMAINS = [
    "www","mail","ftp","smtp","pop","imap","webmail","admin","portal","vpn",
    "remote","api","dev","test","staging","beta","cdn","static","img","images",
    "blog","shop","store","mx","mx1","mx2","ns1","ns2","dns","dns1","dns2",
    "secure","login","auth","sso","app","apps","mobile","m","wap","forum",
    "support","help","docs","wiki","git","gitlab","github","svn","jira",
    "confluence","jenkins","ci","monitor","grafana","kibana","elastic",
    "db","database","sql","mysql","postgres","redis","rabbitmq","kafka",
    "proxy","firewall","router","gateway","vpn2","backup","archive","files",
    "upload","download","media","video","stream","live","chat","irc",
    "intranet","internal","corp","extranet","partner","client","customer",
    "old","new","legacy","v1","v2","v3","beta2","preview","sandbox",
    "uat","qa","preprod","demo","marketing","cms","erp","crm",
    "status","health","metrics","logs","alerts","reporting",
]

lock    = threading.Lock()
results = {"vulnerable": [], "cname_only": [], "nxdomain": [], "alive": []}
stats   = {"tested": 0, "vulnerable": 0}

# ─── DNS query raw ────────────────────────────────────────────────────────────
def dns_query_raw(domain, qtype=1, server="8.8.8.8", timeout=2.5):
    """Retorna lista de respostas: [(type_name, value), ...]"""
    import struct, random

    def build_query(name, qt):
        txid  = random.randint(0, 65535)
        hdr   = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        qname = b""
        for label in name.split("."):
            enc = label.encode()
            qname += struct.pack("B", len(enc)) + enc
        qname += b"\x00"
        return txid, hdr + qname + struct.pack("!HH", qt, 1)

    def parse_name(data, offset, depth=0):
        if depth > 10:
            return "?", offset
        labels, jumped = [], False
        orig_offset = offset
        while offset < len(data):
            l = data[offset]
            if l == 0:
                offset += 1
                break
            elif (l & 0xC0) == 0xC0:
                ptr = ((l & 0x3F) << 8) | data[offset+1]
                if not jumped:
                    orig_offset = offset + 2
                offset, jumped = ptr, True
            else:
                offset += 1
                labels.append(data[offset:offset+l].decode("utf-8", errors="ignore"))
                offset += l
        return ".".join(labels), (orig_offset if jumped else offset)

    try:
        txid, pkt = build_query(domain, qtype)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, (server, 53))
        resp, _ = s.recvfrom(4096)
        s.close()

        if len(resp) < 12:
            return []

        flags   = struct.unpack("!H", resp[2:4])[0]
        ancount = struct.unpack("!H", resp[6:8])[0]
        rcode   = flags & 0x000F

        if rcode == 3:   # NXDOMAIN
            return [("NXDOMAIN", "")]
        if rcode != 0:
            return []

        records = []
        offset  = 12
        # Skip question
        _, offset = parse_name(resp, offset)
        offset  += 4   # QTYPE + QCLASS

        for _ in range(ancount):
            if offset >= len(resp):
                break
            _, offset = parse_name(resp, offset)
            if offset + 10 > len(resp):
                break
            rtype, _, _, rdlen = struct.unpack("!HHIH", resp[offset:offset+10])
            offset += 10
            rdata   = resp[offset:offset+rdlen]
            offset += rdlen

            if rtype == 1 and rdlen == 4:       # A
                records.append(("A", socket.inet_ntoa(rdata)))
            elif rtype == 5:                    # CNAME
                cname, _ = parse_name(resp, offset - rdlen)
                records.append(("CNAME", cname))
            elif rtype == 28 and rdlen == 16:   # AAAA
                records.append(("AAAA", socket.inet_ntop(socket.AF_INET6, rdata)))
            elif rtype == 2:                    # NS
                ns, _ = parse_name(resp, offset - rdlen)
                records.append(("NS", ns))

        return records
    except:
        return []


# ─── HTTP probe sem seguir redirect ──────────────────────────────────────────
def http_probe(host, port=80, timeout=5, use_ssl=False):
    """Faz GET simples e retorna (status, body[:500])."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((socket.gethostbyname(host), port))
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        s.send(req.encode())
        raw = b""
        while len(raw) < 8192:
            chunk = s.recv(2048)
            if not chunk: break
            raw += chunk
        s.close()
        parts  = raw.split(b"\r\n\r\n", 1)
        status = 0
        body   = ""
        if parts:
            first_line = parts[0].split(b"\r\n")[0].decode("utf-8", errors="ignore")
            try: status = int(first_line.split()[1])
            except: pass
        if len(parts) > 1:
            body = parts[1].decode("utf-8", errors="ignore")[:500]
        return status, body
    except:
        return 0, ""


# ─── Check único de subdomínio ────────────────────────────────────────────────
def check_subdomain(fqdn, reporter):
    stats["tested"] += 1

    # 1. DNS lookup
    records = dns_query_raw(fqdn, qtype=1)   # A
    nxdomain = any(r[0] == "NXDOMAIN" for r in records)

    if nxdomain:
        with lock:
            results["nxdomain"].append(fqdn)
        return

    a_records   = [r[1] for r in records if r[0] == "A"]
    cname_recs  = dns_query_raw(fqdn, qtype=5)  # CNAME
    cnames      = [r[1] for r in cname_recs if r[0] == "CNAME"]

    if not a_records and not cnames:
        return

    with lock:
        results["alive"].append(fqdn)

    # 2. Verificar se CNAME aponta para serviço externo não reivindicado
    for cname in cnames:
        cname_lower = cname.lower()
        for pattern, body_sig, service, sev in TAKEOVER_FINGERPRINTS:
            if pattern in cname_lower:
                # Confirmar via HTTP probe
                status, body = http_probe(fqdn, timeout=5)
                if not status:
                    status, body = http_probe(fqdn, port=443, use_ssl=True, timeout=5)

                body_lower = body.lower()
                sig_lower  = body_sig.lower()

                if sig_lower in body_lower or status in (0, 404):
                    with lock:
                        results["vulnerable"].append({
                            "fqdn"    : fqdn,
                            "cname"   : cname,
                            "service" : service,
                            "severity": sev,
                            "status"  : status,
                            "evidence": body[:200],
                        })
                        stats["vulnerable"] += 1

                    reporter.add("Subdomain Takeover", sev,
                                 f"Possível takeover: {fqdn}",
                                 f"CNAME: {cname}\nServiço: {service}\nStatus HTTP: {status}\n"
                                 f"Evidência: {body[:150]}",
                                 {"fqdn": fqdn, "cname": cname, "service": service})
                    print_finding(sev, "Takeover",
                                  f"{fqdn} → {cname} ({service})")
                    return

                # CNAME existe mas resposta ok — apenas informa
                with lock:
                    results["cname_only"].append({
                        "fqdn": fqdn, "cname": cname, "service": service
                    })
                print(f"  {C}[CNAME]{RST} {fqdn} → {DIM}{cname}{RST} ({service})")
                reporter.add("Subdomain", "LOW",
                             f"CNAME para serviço externo: {service}",
                             f"FQDN: {fqdn}\nCNAME: {cname}\nStatus: {status}")
                return

    # 3. Subdomínio vivo sem CNAME suspeito
    if a_records:
        print(f"  {DIM}[alive]{RST} {fqdn} → {', '.join(a_records[:2])}")


# ─── Worker ───────────────────────────────────────────────────────────────────
def worker(domain, q, reporter):
    while not q.empty():
        try:
            sub = q.get_nowait()
        except:
            break
        fqdn = f"{sub}.{domain}"
        check_subdomain(fqdn, reporter)
        q.task_done()


# ─── Wildcard DNS check ───────────────────────────────────────────────────────
def check_wildcard(domain):
    random_sub = f"xq7zm3r4t1k9.{domain}"
    recs = dns_query_raw(random_sub, qtype=1)
    a_recs = [r[1] for r in recs if r[0] == "A"]
    return bool(a_recs), a_recs


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    print_header(
        "SUBDOMAIN TAKEOVER CHECKER v2",
        "CNAME Dangling | 30+ Serviços Cloud | DNS Wildcard Detection",
        color=Y
    )

    parser = argparse.ArgumentParser(description="Subdomain Takeover Checker — Python puro")
    parser.add_argument("-d","--domain",    required=True, help="Domínio alvo")
    parser.add_argument("--wordlist",       default=None, help="Wordlist de subdomínios")
    parser.add_argument("--threads",        type=int, default=50, help="Threads paralelas")
    parser.add_argument("--timeout",        type=float, default=2.5, help="Timeout DNS")
    parser.add_argument("--output",         default=None, help="Base do arquivo de saída")
    args = parser.parse_args()

    domain   = args.domain.lower().strip()
    reporter = Reporter("Subdomain Takeover Checker", domain)

    # Resolve domínio principal
    main_ip = resolve(domain)
    reporter.set_meta("IP principal", main_ip or "N/A")

    print(f"  {B}[*]{RST} Domínio : {W}{domain}{RST} ({main_ip or 'N/A'})")
    print(f"  {B}[*]{RST} Início  : {datetime.now().strftime('%H:%M:%S')}\n")
    print(f"  {C}{'─'*60}{RST}")

    # ── Wildcard check ──
    print(f"  {Y}[Wildcard]{RST} Verificando DNS wildcard...")
    has_wildcard, wc_ips = check_wildcard(domain)
    if has_wildcard:
        print(f"  {Y}[!]{RST} DNS Wildcard detectado → {', '.join(wc_ips)}")
        print(f"      {DIM}Falsos positivos são prováveis — confirme manualmente.{RST}")
        reporter.add("DNS", "MEDIUM",
                     "DNS Wildcard ativo",
                     f"Qualquer subdomínio resolve para: {', '.join(wc_ips)}\n"
                     f"Isso pode gerar falsos positivos na varredura.",
                     {"wildcard_ips": wc_ips})
    else:
        print(f"  {G}[+]{RST} Sem wildcard DNS — varredura confiável\n")

    # ── Carregar subdomínios ──
    if args.wordlist:
        try:
            with open(args.wordlist) as f:
                subs = [l.strip() for l in f if l.strip()]
            print(f"  {B}[*]{RST} Wordlist: {args.wordlist} ({len(subs)} subdomínios)")
        except:
            print(f"  {R}[!]{RST} Wordlist não encontrada — usando padrão")
            subs = DEFAULT_SUBDOMAINS
    else:
        subs = DEFAULT_SUBDOMAINS
        print(f"  {B}[*]{RST} Usando {len(subs)} subdomínios padrão")

    print(f"  {B}[*]{RST} Threads : {args.threads}\n")
    print(f"  {Y}[SCAN]{RST} Iniciando...\n")

    q = Queue()
    for s in subs:
        q.put(s)

    threads = [
        threading.Thread(target=worker, args=(domain, q, reporter), daemon=True)
        for _ in range(min(args.threads, len(subs)))
    ]
    for t in threads:
        t.start()

    total = len(subs)
    while any(t.is_alive() for t in threads):
        done = stats["tested"]
        pct  = int((done/total)*40) if total else 40
        bar  = f"{G}{'█'*pct}{DIM}{'░'*(40-pct)}{RST}"
        vuln_str = f" {R}[{stats['vulnerable']} vulnerável(is)]{RST}" if stats["vulnerable"] else ""
        print(f"\r  [{bar}] {done}/{total}{vuln_str}", end="", flush=True)
        time.sleep(0.3)

    for t in threads:
        t.join()
    print(f"\r  [{G}{'█'*40}{RST}] {total}/{total} {G}✓{RST}    \n")

    # ── Resumo ──
    print(f"{C}{'═'*62}{RST}")
    print(f"{BOLD}  RESUMO — {domain}{RST}")
    print(f"{C}{'═'*62}{RST}")
    print(f"  Subdomínios testados  : {stats['tested']}")
    print(f"  Subdomínios ativos    : {len(results['alive'])}")
    print(f"  CNAMEs suspeitos      : {len(results['cname_only'])}")
    print(f"  {R}Vulneráveis (takeover): {len(results['vulnerable'])}{RST}")

    if results["vulnerable"]:
        print(f"\n  {R}{BOLD}VULNERABILIDADES DE TAKEOVER:{RST}")
        for v in results["vulnerable"]:
            sc = severity_color(v["severity"])
            print(f"\n  {sc}[{v['severity']}]{RST} {W}{v['fqdn']}{RST}")
            print(f"         CNAME   : {v['cname']}")
            print(f"         Serviço : {v['service']}")
            print(f"         Status  : {v['status']}")
            print(f"         Evidência: {DIM}{v['evidence'][:100]}{RST}")

    reporter.set_meta("Testados", stats["tested"])
    reporter.set_meta("Ativos", len(results["alive"]))
    reporter.set_meta("Vulneráveis", len(results["vulnerable"]))

    if args.output:
        reporter.save_all(args.output)
    else:
        print(f"\n  {DIM}Use --output <base> para salvar TXT/JSON/HTML{RST}")

if __name__ == "__main__":
    main()
