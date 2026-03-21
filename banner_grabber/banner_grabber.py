#!/usr/bin/env python3
"""
╔══════════════════════════════════════════╗
║        ADVANCED BANNER GRABBER           ║
║  Fingerprinting | Multi-protocolo | SSL  ║
╚══════════════════════════════════════════╝
Uso:
  python3 banner_grabber.py -t 192.168.1.1 -p 22,80,443,21,25
  python3 banner_grabber.py -t example.com --all-common --threads 20
  python3 banner_grabber.py -t 10.0.0.1 -p 80 --http-full --output resultado.txt
"""

import socket
import ssl
import threading
import argparse
import sys
import time
import re
import struct
from datetime import datetime
from queue import Queue

R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
M="\033[95m"; C="\033[96m"; W="\033[97m"; DIM="\033[2m"; RST="\033[0m"; BOLD="\033[1m"

# ─── Probes por protocolo/porta ────────────────────────────────────────────────
PROBES = {
    # (probe_bytes, use_ssl, description)
    21:  (b"",                        False, "FTP"),
    22:  (b"",                        False, "SSH"),
    23:  (b"",                        False, "Telnet"),
    25:  (b"EHLO grabber\r\n",        False, "SMTP"),
    80:  (b"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n", False, "HTTP"),
    110: (b"",                        False, "POP3"),
    143: (b"",                        False, "IMAP"),
    443: (b"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n", True,  "HTTPS"),
    445: (b"",                        False, "SMB"),
    3306:(b"\x00",                    False, "MySQL"),
    5432:(b"",                        False, "PostgreSQL"),
    6379:(b"*1\r\n$4\r\nINFO\r\n",   False, "Redis"),
    8080:(b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n", False, "HTTP-Alt"),
    8443:(b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n", True,  "HTTPS-Alt"),
    27017:(b"\x3a\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00"
           b"\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\xff"
           b"\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x6d\x61\x73\x74\x65\x72\x00\x01"
           b"\x00\x00\x00\x00", False, "MongoDB"),
    9200:(b"GET / HTTP/1.0\r\n\r\n",  False, "Elasticsearch"),
    11211:(b"version\r\n",            False, "Memcached"),
    2181:(b"ruok",                    False, "Zookeeper"),
}

COMMON_PORTS = [21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,
                5432,5900,6379,8080,8443,8888,9200,27017,11211,2181]

lock    = threading.Lock()
results = {}

def print_banner():
    print(f"""
{B}╔{'═'*54}╗
║  {W}{BOLD}██████╗  █████╗ ███╗  ██╗███╗  ██╗███████╗██████╗   {B}║
║  {W}{BOLD}██╔══██╗██╔══██╗████╗ ██║████╗ ██║██╔════╝██╔══██╗  {B}║
║  {W}{BOLD}██████╔╝███████║██╔██╗██║██╔██╗██║█████╗  ██████╔╝  {B}║
║  {W}{BOLD}██╔══██╗██╔══██║██║╚████║██║╚████║██╔══╝  ██╔══██╗  {B}║
║  {W}{BOLD}██████╔╝██║  ██║██║ ╚███║██║ ╚███║███████╗██║  ██║  {B}║
║  {W}{BOLD}╚═════╝ ╚═╝  ╚═╝╚═╝  ╚══╝╚═╝  ╚══╝╚══════╝╚═╝  ╚═╝  {B}║
║{C}            B A N N E R   G R A B B E R              {B}║
╚{'═'*54}╝{RST}
{DIM}  [*] Apenas em hosts com autorização.{RST}
""")

# ─── Fingerprint por padrão de banner ─────────────────────────────────────────
FINGERPRINTS = [
    (r"OpenSSH[_\s]([\d.]+)",                    "SSH",         "OpenSSH {}"),
    (r"SSH-([\d.]+)-(.+)",                        "SSH",         "SSH {} - {}"),
    (r"Apache/([\d.]+)",                          "Webserver",   "Apache {}"),
    (r"nginx/([\d.]+)",                           "Webserver",   "nginx {}"),
    (r"Microsoft-IIS/([\d.]+)",                   "Webserver",   "IIS {}"),
    (r"220.*(vsftpd|proftpd|FileZilla|wu-ftp)",  "FTP",         "{}"),
    (r"Postfix|Sendmail|Exim|qmail",              "Mail",        "{}"),
    (r"MySQL.*Ver ([\d.]+)",                      "Database",    "MySQL {}"),
    (r"PostgreSQL",                               "Database",    "PostgreSQL"),
    (r"\+PONG|redis_version:([\d.]+)",            "Cache",       "Redis {}"),
    (r'"version"\s*:\s*"([\d.]+)"',               "NoSQL",       "MongoDB {}"),
    (r"ElasticSearch|\"cluster_name\"",           "Search",      "Elasticsearch"),
    (r"VERSION ([\d.]+)",                         "Cache",       "Memcached {}"),
    (r"imok",                                     "Coordination","Zookeeper"),
    (r"RFB ([\d.]+)",                             "Remote",      "VNC {}"),
    (r"Microsoft Windows|Windows NT",             "OS",          "Windows"),
    (r"\+OK",                                     "Mail",        "POP3"),
    (r"\* OK",                                    "Mail",        "IMAP"),
    (r"SMB",                                      "File",        "Samba/SMB"),
]

def fingerprint_banner(banner):
    for pattern, category, name_fmt in FINGERPRINTS:
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            try:
                name = name_fmt.format(*m.groups()) if m.groups() else name_fmt
            except:
                name = name_fmt
            return category, name
    return "Unknown", ""

# ─── Grab banner HTTP completo ─────────────────────────────────────────────────
def grab_http_full(host, port, use_ssl, timeout):
    """Extrai headers HTTP detalhados."""
    extra = {}
    request = (f"GET / HTTP/1.1\r\n"
               f"Host: {host}\r\n"
               f"User-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n"
               f"Accept: */*\r\n"
               f"Connection: close\r\n\r\n").encode()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((socket.gethostbyname(host), port))
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        s.send(request)
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            response += chunk
            if b"\r\n\r\n" in response: break  # Só precisa dos headers
        s.close()
        headers = response.split(b"\r\n\r\n")[0].decode("utf-8", errors="ignore")
        for line in headers.split("\r\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                extra[k.strip()] = v.strip()
        return headers[:500], extra
    except:
        return "", {}

# ─── Grab banner genérico ──────────────────────────────────────────────────────
def grab_banner(host, port, timeout, http_full):
    ip = socket.gethostbyname(host)
    config = PROBES.get(port, (b"", False, "Unknown"))
    probe_raw, use_ssl, svc_hint = config

    # Substitui {host} no probe
    if b"{host}" in probe_raw:
        probe_raw = probe_raw.replace(b"{host}", host.encode())

    banner = ""
    ssl_info = {}
    t0 = time.time()

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        conn_result = s.connect_ex((ip, port))
        if conn_result != 0:
            s.close()
            return None

        if use_ssl:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=host)
                cert = s.getpeercert(binary_form=False)
                if cert:
                    ssl_info["subject"] = dict(x[0] for x in cert.get("subject", []))
                    ssl_info["issuer"]  = dict(x[0] for x in cert.get("issuer", []))
                    ssl_info["expires"] = cert.get("notAfter", "")
                    ssl_info["cipher"]  = s.cipher()[0] if s.cipher() else ""
            except ssl.SSLError as e:
                ssl_info["ssl_error"] = str(e)

        if probe_raw:
            s.send(probe_raw)

        s.settimeout(timeout)
        raw = b""
        while True:
            try:
                chunk = s.recv(1024)
                if not chunk: break
                raw += chunk
                if len(raw) > 4096: break
            except:
                break
        s.close()

        banner = raw.decode("utf-8", errors="ignore").strip()
        rtt    = round((time.time() - t0) * 1000, 1)

    except Exception as e:
        return None

    category, fp_name = fingerprint_banner(banner)

    result = {
        "port"     : port,
        "service"  : svc_hint,
        "banner"   : banner[:300],
        "category" : category,
        "fp_name"  : fp_name,
        "ssl"      : bool(use_ssl),
        "ssl_info" : ssl_info,
        "rtt"      : rtt,
    }

    # HTTP full headers
    if http_full and port in (80,443,8080,8443):
        full, hdrs = grab_http_full(host, port, use_ssl, timeout)
        result["http_headers"] = hdrs

    return result

# ─── Worker ───────────────────────────────────────────────────────────────────
def worker(host, q, timeout, http_full):
    while not q.empty():
        try:
            port = q.get_nowait()
        except:
            break
        result = grab_banner(host, port, timeout, http_full)
        if result:
            with lock:
                results[port] = result
                display_result(host, result)
        q.task_done()

# ─── Display ──────────────────────────────────────────────────────────────────
def display_result(host, r):
    port     = r["port"]
    service  = r["service"]
    category = r["category"]
    fp       = r["fp_name"]
    ssl_mark = f"{G}[SSL]{RST} " if r["ssl"] else ""
    rtt_str  = f"{DIM}{r['rtt']}ms{RST}"

    print(f"\n  {G}{'─'*56}{RST}")
    print(f"  {B}PORT {Y}{port:<6}{RST} {W}{service:<12}{RST} {ssl_mark}{rtt_str}")

    if fp:
        print(f"  {G}[Fingerprint]{RST} {M}{category}{RST} → {W}{fp}{RST}")

    if r["banner"]:
        banner_lines = r["banner"].split("\n")[:5]
        for line in banner_lines:
            if line.strip():
                print(f"  {DIM}│ {line[:80]}{RST}")

    if r["ssl_info"]:
        info = r["ssl_info"]
        if "subject" in info:
            cn = info["subject"].get("commonName","")
            print(f"  {C}[SSL] CN={cn}{RST}")
        if "expires" in info:
            print(f"  {C}[SSL] Expira: {info['expires']}{RST}")
        if "cipher" in info:
            print(f"  {C}[SSL] Cipher: {info['cipher']}{RST}")

    if "http_headers" in r:
        hdrs = r.get("http_headers", {})
        important = ["Server","X-Powered-By","Set-Cookie","Content-Type",
                     "X-Frame-Options","Strict-Transport-Security"]
        for h in important:
            if h in hdrs:
                print(f"  {Y}[HTTP]{RST} {h}: {hdrs[h][:80]}")

# ─── Main ──────────────────────────────────────────────────────────────────────
def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Advanced Banner Grabber — Python puro")
    parser.add_argument("-t","--target",    required=True, help="Host alvo (IP ou domínio)")
    parser.add_argument("-p","--ports",     default=None, help="Portas: 22,80,443")
    parser.add_argument("--all-common",    action="store_true", help="Testar todas as portas comuns")
    parser.add_argument("--timeout",       type=float, default=3.0, help="Timeout em segundos")
    parser.add_argument("--threads",       type=int, default=20, help="Threads paralelas")
    parser.add_argument("--http-full",     action="store_true", help="Coletar headers HTTP completos")
    parser.add_argument("--output",        default=None, help="Salvar resultados")
    args = parser.parse_args()

    # Resolver host
    try:
        ip = socket.gethostbyname(args.target)
        hostname = socket.getfqdn(args.target)
    except socket.gaierror as e:
        print(f"{R}[ERRO] Não foi possível resolver '{args.target}': {e}{RST}")
        sys.exit(1)

    # Definir portas
    if args.all_common:
        ports = COMMON_PORTS
    elif args.ports:
        ports = []
        for p in args.ports.split(","):
            p = p.strip()
            if "-" in p:
                a, b = p.split("-")
                ports.extend(range(int(a), int(b)+1))
            else:
                ports.append(int(p))
    else:
        ports = COMMON_PORTS[:10]

    print(f"  {B}[*]{RST} Alvo      : {W}{args.target}{RST} ({ip})")
    print(f"  {B}[*]{RST} Hostname  : {hostname}")
    print(f"  {B}[*]{RST} Portas    : {len(ports)}")
    print(f"  {B}[*]{RST} Threads   : {args.threads}")
    print(f"  {B}[*]{RST} Timeout   : {args.timeout}s")
    print(f"  {B}[*]{RST} HTTP Full : {'Sim' if args.http_full else 'Não'}")
    print(f"\n  {Y}[GRABBING]{RST} {datetime.now().strftime('%H:%M:%S')}")

    q = Queue()
    for p in ports: q.put(p)

    threads = [threading.Thread(target=worker,
                                args=(args.target, q, args.timeout, args.http_full),
                                daemon=True)
               for _ in range(min(args.threads, len(ports)))]
    for t in threads: t.start()
    for t in threads: t.join()

    # Resumo
    print(f"\n\n{C}{'═'*60}{RST}")
    print(f"{BOLD}  RESUMO{RST}")
    print(f"{C}{'═'*60}{RST}")
    print(f"  Portas testadas : {len(ports)}")
    print(f"  Banners obtidos : {G}{len(results)}{RST}")

    if results:
        print(f"\n  {BOLD}SERVIÇOS DETECTADOS:{RST}")
        for port in sorted(results.keys()):
            r = results[port]
            print(f"  {Y}{port:<6}{RST} {G}{r['service']:<12}{RST} {M}{r['fp_name'] or r['category']}{RST}")

    if args.output:
        with open(args.output,"w") as f:
            f.write(f"Banner Grabber — {args.target} — {datetime.now()}\n")
            f.write("="*60+"\n")
            for port, r in sorted(results.items()):
                f.write(f"\nPORT {port} ({r['service']})\n")
                f.write(f"Fingerprint: {r['fp_name']}\n")
                f.write(f"Banner:\n{r['banner']}\n")
                if r["ssl_info"]:
                    f.write(f"SSL: {r['ssl_info']}\n")
        print(f"\n  {G}[✓] Salvo em: {args.output}{RST}")

if __name__ == "__main__":
    main()
