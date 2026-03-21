#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║           ADVANCED PORT SCANNER v2                       ║
║  TCP | UDP | OS Fingerprint | Version | JSON/HTML output ║
╚══════════════════════════════════════════════════════════╝
Uso:
  python3 port_scanner.py -t 192.168.1.1 -p 1-1024 --threads 200 --timeout 0.5
  python3 port_scanner.py -t 192.168.1.1 -p 22,80,443 --stealth --banner --os-detect
  python3 port_scanner.py -t 192.168.1.0/24 --top-ports --output resultado --format all
  python3 port_scanner.py -t 192.168.1.1 --udp --udp-ports 53,123,161,500
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))
from common import Reporter, G, R, Y, B, M, C, W, DIM, RST, BOLD, print_finding

import socket
import threading
import argparse
import time
import random
import struct
from queue import Queue
from datetime import datetime

# ─── Cores ANSI ───────────────────────────────────────────────────────────────
R  = "\033[91m"
G  = "\033[92m"
Y  = "\033[93m"
B  = "\033[94m"
M  = "\033[95m"
C  = "\033[96m"
W  = "\033[97m"
DIM= "\033[2m"
RST= "\033[0m"
BOLD="\033[1m"

# ─── Portas mais comuns com descrição ─────────────────────────────────────────
TOP_PORTS = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 111:"RPC", 135:"MSRPC", 139:"NetBIOS",
    143:"IMAP", 443:"HTTPS", 445:"SMB", 993:"IMAPS", 995:"POP3S",
    1723:"PPTP", 3306:"MySQL", 3389:"RDP", 5900:"VNC", 8080:"HTTP-Alt",
    8443:"HTTPS-Alt", 8888:"HTTP-Dev", 27017:"MongoDB", 6379:"Redis",
    5432:"PostgreSQL", 1433:"MSSQL", 2049:"NFS", 161:"SNMP", 162:"SNMPTRAP",
    389:"LDAP", 636:"LDAPS", 5061:"SIP-TLS", 5060:"SIP", 69:"TFTP"
}

BANNER_PROBES = {
    21:  b"",
    22:  b"",
    23:  b"",
    25:  b"EHLO cybersec\r\n",
    80:  b"HEAD / HTTP/1.0\r\n\r\n",
    8080:b"HEAD / HTTP/1.0\r\n\r\n",
    110: b"",
    143: b"",
    443: b"",
}

lock = threading.Lock()
results = {}

# ─── OS Fingerprint por TTL ────────────────────────────────────────────────────
TTL_OS_MAP = [
    (255, 255, "Cisco IOS / Network Device"),
    (128, 128, "Windows (TTL=128)"),
    (127, 127, "Windows (TTL=127, VPN?)"),
    (64,  64,  "Linux / macOS (TTL=64)"),
    (63,  63,  "Linux (TTL=63, 1 hop)"),
    (255, 200, "Solaris / AIX"),
    (60,  60,  "macOS (variante)"),
    (32,  32,  "Windows 95/98"),
]

SERVICE_VERSIONS = {
    # Banner pattern → (service_name, version_regex)
    22:  [("OpenSSH",  r"OpenSSH[_\s]([\d.p]+)"),
          ("SSH",      r"SSH-[\d.]+-(.+)")],
    21:  [("vsftpd",   r"vsftpd ([\d.]+)"),
          ("ProFTPD",  r"ProFTPD ([\d.]+)"),
          ("FileZilla",r"FileZilla Server ([\d.]+)")],
    25:  [("Postfix",  r"Postfix"),
          ("Exim",     r"Exim ([\d.]+)"),
          ("Sendmail", r"Sendmail")],
    80:  [("Apache",   r"Apache/([\d.]+)"),
          ("nginx",    r"nginx/([\d.]+)"),
          ("IIS",      r"IIS/([\d.]+)")],
    3306:[("MySQL",    r"([\d.]+)-")],
    5432:[("PostgreSQL",r"PostgreSQL")],
    6379:[("Redis",    r"redis_version:([\d.]+)")],
}

def detect_service_version(port, banner):
    import re
    if not banner or port not in SERVICE_VERSIONS:
        return ""
    for svc_name, pattern in SERVICE_VERSIONS[port]:
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            groups = m.groups()
            version = groups[0] if groups else ""
            return f"{svc_name} {version}".strip()
    return ""

def os_from_ttl(ttl):
    if ttl is None:
        return "?"
    for lo, hi, name in TTL_OS_MAP:
        if lo <= ttl <= hi:
            return name
    if ttl > 200:
        return "Network Device / Solaris"
    if ttl > 100:
        return "Windows"
    if ttl > 50:
        return "Linux / macOS"
    return f"Desconhecido (TTL={ttl})"

def icmp_ping_ttl(ip, timeout=1.5):
    """Envia ICMP Echo Request e retorna TTL para OS guess."""
    try:
        import os as _os
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.settimeout(timeout)

        def cksum(data):
            s = 0
            for i in range(0, len(data), 2):
                s += (data[i] << 8) + (data[i+1] if i+1 < len(data) else 0)
            s = (s >> 16) + (s & 0xffff)
            return ~(s + (s >> 16)) & 0xffff

        pid   = _os.getpid() & 0xFFFF
        seq   = random.randint(1, 65535)
        hdr   = struct.pack("!BBHHH", 8, 0, 0, pid, seq)
        data  = b"cybersec_v2"
        hdr   = struct.pack("!BBHHH", 8, 0, cksum(hdr+data), pid, seq)
        packet = hdr + data

        s.sendto(packet, (ip, 0))
        raw, _ = s.recvfrom(1024)
        ttl = raw[8] if len(raw) > 8 else None
        s.close()
        return ttl
    except:
        return None

def detect_os(ip):
    """Tenta detectar OS via TTL do ICMP."""
    ttl = icmp_ping_ttl(ip)
    if ttl:
        return os_from_ttl(ttl), ttl
    return "N/A (ICMP bloqueado)", None

# ─── UDP Scan ──────────────────────────────────────────────────────────────────
UDP_PROBES = {
    53:  (b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03", "DNS"),
    123: (b"\x1b" + b"\x00"*47, "NTP"),
    161: (b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x71\xb4\x08\x0b\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00", "SNMP"),
    500: (b"\x00"*28 + b"\x01\x10\x02\x00" + b"\x00"*24, "IKE"),
    1900:(b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: ssdp:all\r\nMX: 1\r\n\r\n", "SSDP"),
    5353:(b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05local\x00\x00\xff\x00\x01", "mDNS"),
}

def udp_scan_port(ip, port, timeout=2.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        probe, svc = UDP_PROBES.get(port, (b"\x00", "UDP"))
        s.sendto(probe, (ip, port))
        data, _ = s.recvfrom(1024)
        s.close()
        return True, svc, data[:80].decode("utf-8", errors="ignore")
    except socket.timeout:
        # Sem resposta — porta pode estar aberta (UDP é sem conexão)
        return None, UDP_PROBES.get(port, (b"", "UDP"))[1], ""
    except:
        return False, "", ""



# ─── Banner ASCII ──────────────────────────────────────────────────────────────
def print_banner():
    print(f"""
{C}╔{'═'*52}╗
║{M}{BOLD}  ██████╗ ███████╗ ██████╗ █████╗ ███╗  ██╗  {C}║
║{M}{BOLD}  ██╔══╝ ██╔════╝██╔════╝██╔══██╗████╗ ██║  {C}║
║{M}{BOLD}  ███╗   ███████╗██║     ███████║██╔██╗██║  {C}║
║{M}{BOLD}  ██╔╝   ╚════██║██║     ██╔══██║██║╚████║  {C}║
║{M}{BOLD}  ██║    ███████║╚██████╗██║  ██║██║ ╚███║  {C}║
║{M}{BOLD}  ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝  {C}║
║{W}         A D V A N C E D   P O R T   S C A N N E R       {C}║
╚{'═'*52}╝{RST}
{DIM}  [*] Apenas para fins educacionais e testes autorizados{RST}
""")

# ─── Resolução de host ─────────────────────────────────────────────────────────
def resolve_host(target):
    try:
        ip = socket.gethostbyname(target)
        hostname = socket.getfqdn(target)
        return ip, hostname
    except socket.gaierror as e:
        print(f"{R}[ERRO] Não foi possível resolver '{target}': {e}{RST}")
        sys.exit(1)

# ─── Expande range de portas ───────────────────────────────────────────────────
def parse_ports(port_str):
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end)+1))
        else:
            ports.append(int(part))
    return sorted(set(ports))

# ─── Expande CIDR /24 simples ──────────────────────────────────────────────────
def expand_cidr(target):
    if "/" not in target:
        return [target]
    base, prefix = target.rsplit(".", 1)[0], int(target.split("/")[1])
    if prefix == 24:
        base_ip = target.split("/")[0].rsplit(".", 1)[0]
        return [f"{base_ip}.{i}" for i in range(1, 255)]
    return [target.split("/")[0]]

# ─── Grab banner ──────────────────────────────────────────────────────────────
def grab_banner(ip, port, timeout=2.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        probe = BANNER_PROBES.get(port, b"")
        if probe:
            s.send(probe)
        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        s.close()
        return banner[:80] if banner else ""
    except:
        return ""

# ─── Scan de porta individual ──────────────────────────────────────────────────
def scan_port(ip, port, timeout, grab_ban, stealth):
    if stealth:
        time.sleep(random.uniform(0.01, 0.1))

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()

        if result == 0:
            service = TOP_PORTS.get(port, "desconhecido")
            banner  = ""
            version = ""
            if grab_ban:
                banner  = grab_banner(ip, port, timeout)
                version = detect_service_version(port, banner)
            return True, service, banner, version
        return False, "", "", ""
    except:
        return False, "", "", ""


# ─── Worker thread ─────────────────────────────────────────────────────────────
def worker(ip, queue, timeout, grab_ban, stealth, stats):
    while not queue.empty():
        try:
            port = queue.get_nowait()
        except:
            break

        is_open, service, banner, version = scan_port(ip, port, timeout, grab_ban, stealth)
        stats["scanned"] += 1

        if is_open:
            with lock:
                results[port] = {"service": service, "banner": banner, "version": version}
                svc_label  = f"{G}{service:<15}{RST}" if service != "desconhecido" else f"{DIM}{'desconhecido':<15}{RST}"
                ver_str    = f" {M}[{version}]{RST}" if version else ""
                banner_str = f" {DIM}│ {banner[:55]}{RST}" if banner and not version else ""
                print(f"  {G}[ABERTA]{RST} {W}{ip}{RST}:{Y}{port:<6}{RST} → {svc_label}{ver_str}{banner_str}")

        queue.task_done()


# ─── Scan principal ────────────────────────────────────────────────────────────
def run_scan(ip, ports, num_threads, timeout, grab_ban, stealth):
    queue = Queue()
    stats = {"scanned": 0}
    for p in ports:
        queue.put(p)

    threads = []
    for _ in range(min(num_threads, len(ports))):
        t = threading.Thread(target=worker, args=(ip, queue, timeout, grab_ban, stealth, stats), daemon=True)
        t.start()
        threads.append(t)

    # Barra de progresso simples
    total = len(ports)
    while any(t.is_alive() for t in threads):
        done = stats["scanned"]
        pct = int((done / total) * 40) if total > 0 else 40
        bar = f"{G}{'█'*pct}{DIM}{'░'*(40-pct)}{RST}"
        print(f"\r  [{bar}] {done}/{total} portas", end="", flush=True)
        time.sleep(0.2)

    for t in threads:
        t.join()
    print(f"\r  [{G}{'█'*40}{RST}] {total}/{total} portas {G}✓{RST}    ")

# ─── Saída de resultados ───────────────────────────────────────────────────────
def print_summary(ip, hostname, ports, elapsed, output_base=None, format_out="txt",
                  os_guess="", udp_results=None):
    reporter = Reporter("Port Scanner", ip)
    reporter.set_meta("Hostname", hostname)
    reporter.set_meta("OS Detectado", os_guess or "N/A")
    reporter.set_meta("Portas TCP testadas", len(ports))
    reporter.set_meta("Portas TCP abertas", len(results))
    reporter.set_meta("Duração", f"{elapsed:.2f}s")

    lines = []
    lines.append(f"\n{C}{'─'*60}{RST}")
    lines.append(f"{BOLD}{W}  RESUMO DO SCAN{RST}")
    lines.append(f"{C}{'─'*60}{RST}")
    lines.append(f"  Alvo     : {W}{ip}{RST} ({hostname})")
    lines.append(f"  OS       : {M}{os_guess or 'N/A'}{RST}")
    lines.append(f"  Portas   : {len(ports)} verificadas")
    lines.append(f"  Abertas  : {G}{len(results)}{RST}")
    lines.append(f"  Tempo    : {elapsed:.2f}s")
    lines.append(f"{C}{'─'*60}{RST}")

    if results:
        lines.append(f"\n  {BOLD}PORTAS TCP ABERTAS:{RST}")
        for port in sorted(results.keys()):
            svc = results[port]["service"]
            ban = results[port]["banner"]
            ver = results[port].get("version","")
            lines.append(f"  {Y}{port:<6}{RST} → {G}{svc}{RST} {M}{ver}{RST}")
            if ban and not ver:
                lines.append(f"         {DIM}{ban}{RST}")
            reporter.add("Port", "INFO", f"TCP/{port} aberto — {svc}",
                         ver or ban,
                         {"port": port, "service": svc, "version": ver, "banner": ban})

    if udp_results:
        lines.append(f"\n  {BOLD}PORTAS UDP:{RST}")
        for port, (status, svc, banner) in sorted(udp_results.items()):
            state = "aberta" if status else "aberta|filtrada"
            lines.append(f"  {C}{port:<6}{RST} UDP {G}{svc:<15}{RST} {DIM}{state}{RST}")
            reporter.add("Port", "LOW", f"UDP/{port} {state} — {svc}",
                         banner, {"port": port, "service": svc, "protocol": "UDP"})

    if not results and not udp_results:
        lines.append(f"\n  {R}Nenhuma porta aberta encontrada.{RST}")

    for l in lines:
        print(l)

    if output_base:
        if format_out in ("all", "txt"):
            reporter.save_txt(output_base + ".txt")
        if format_out in ("all", "json"):
            reporter.save_json(output_base + ".json")
        if format_out in ("all", "html"):
            reporter.save_html(output_base + ".html")
        if format_out == "all":
            print(f"\n  {G}[✓]{RST} Relatórios: {output_base}.{{txt,json,html}}")
        else:
            print(f"\n  {G}[✓]{RST} Salvo em: {output_base}.{format_out}")


# ─── Main ──────────────────────────────────────────────────────────────────────
def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Advanced Port Scanner v2 — Python puro",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-t", "--target",    required=True, help="IP, hostname ou CIDR /24")
    parser.add_argument("-p", "--ports",     default=None,  help="Portas: 1-1024, 22,80,443")
    parser.add_argument("--top-ports",       action="store_true", help="Escanear top 34 portas")
    parser.add_argument("--threads",         type=int, default=150, help="Número de threads (padrão: 150)")
    parser.add_argument("--timeout",         type=float, default=0.5, help="Timeout por porta em seg")
    parser.add_argument("--banner",          action="store_true", help="Tentar capturar banners")
    parser.add_argument("--stealth",         action="store_true", help="Modo furtivo (delay aleatório)")
    parser.add_argument("--os-detect",       action="store_true", help="Detectar OS via TTL (requer root para ICMP)")
    parser.add_argument("--udp",             action="store_true", help="Scan UDP nas portas comuns")
    parser.add_argument("--udp-ports",       default="53,123,161,500,1900,5353",
                        help="Portas UDP (padrão: 53,123,161,500,1900,5353)")
    parser.add_argument("--output",          default=None, help="Base do arquivo de saída (sem extensão)")
    parser.add_argument("--format",          default="all", choices=["txt","json","html","all"],
                        help="Formato de saída (padrão: all)")
    args = parser.parse_args()

    if args.top_ports:
        ports = sorted(TOP_PORTS.keys())
    elif args.ports:
        ports = parse_ports(args.ports)
    else:
        ports = list(range(1, 1025))

    targets = expand_cidr(args.target)

    for target in targets:
        ip, hostname = resolve_host(target)

        print(f"  {B}[*]{RST} Alvo     : {W}{ip}{RST} ({DIM}{hostname}{RST})")
        print(f"  {B}[*]{RST} Portas   : {len(ports)} ({ports[0]}–{ports[-1]})")
        print(f"  {B}[*]{RST} Threads  : {args.threads}")
        print(f"  {B}[*]{RST} Timeout  : {args.timeout}s")
        print(f"  {B}[*]{RST} Stealth  : {'Ativado' if args.stealth else 'Desativado'}")
        print(f"  {B}[*]{RST} Banners  : {'Ativado' if args.banner else 'Desativado'}")
        print(f"  {B}[*]{RST} OS Detect: {'Ativado' if args.os_detect else 'Desativado'}")
        print(f"\n  {Y}[SCAN INICIADO]{RST} {datetime.now().strftime('%H:%M:%S')}\n")

        # OS Detection
        os_guess = ""
        if args.os_detect:
            print(f"  {Y}[OS]{RST} Detectando sistema operacional via ICMP TTL...")
            os_guess, ttl = detect_os(ip)
            if ttl:
                print(f"  {G}[OS]{RST} {M}{os_guess}{RST} {DIM}(TTL={ttl}){RST}\n")
            else:
                print(f"  {DIM}[OS] ICMP bloqueado — tente com sudo{RST}\n")

        t0 = time.time()
        results.clear()
        run_scan(ip, ports, args.threads, args.timeout, args.banner, args.stealth)
        elapsed = time.time() - t0

        # UDP scan
        udp_results = {}
        if args.udp:
            udp_ports = [int(p.strip()) for p in args.udp_ports.split(",")]
            print(f"\n  {Y}[UDP]{RST} Scan em {len(udp_ports)} portas UDP...")
            for uport in udp_ports:
                status, svc, banner = udp_scan_port(ip, uport, args.timeout*2)
                if status is not False:
                    udp_results[uport] = (status, svc, banner)
                    state = "aberta" if status else "aberta|filtrada"
                    print(f"  {C}[UDP]{RST} {W}{ip}{RST}:{Y}{uport:<6}{RST} {G}{svc:<12}{RST} {DIM}{state}{RST}")

        print_summary(ip, hostname, ports, elapsed, args.output, args.format,
                      os_guess, udp_results if udp_results else None)

if __name__ == "__main__":
    main()
