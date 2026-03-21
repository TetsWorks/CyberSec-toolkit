#!/usr/bin/env python3
"""
╔══════════════════════════════════════════╗
║       ADVANCED NETWORK SCANNER           ║
║   ARP Sweep | ICMP Ping | OS Detect      ║
╚══════════════════════════════════════════╝
Uso (ARP requer root):
  python3 network_scanner.py --range 192.168.1.0/24
  python3 network_scanner.py --range 192.168.1.1-192.168.1.50 --method icmp
  python3 network_scanner.py --range 10.0.0.0/24 --method arp --timeout 1 --threads 100
"""

import socket
import struct
import sys
import os
import time
import threading
import argparse
import random
import fcntl
import ipaddress
from datetime import datetime

R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
M="\033[95m"; C="\033[96m"; W="\033[97m"; DIM="\033[2m"; RST="\033[0m"; BOLD="\033[1m"

lock    = threading.Lock()
hosts   = {}
stats   = {"sent":0,"alive":0}

def print_banner():
    print(f"""
{G}╔{'═'*54}╗
║  {W}{BOLD}███╗   ██╗███████╗████████╗███████╗ ██████╗  {G}║
║  {W}{BOLD}████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝  {G}║
║  {W}{BOLD}██╔██╗ ██║█████╗     ██║   ███████╗██║       {G}║
║  {W}{BOLD}██║╚██╗██║██╔══╝     ██║   ╚════██║██║       {G}║
║  {W}{BOLD}██║ ╚████║███████╗   ██║   ███████║╚██████╗  {G}║
║  {W}{BOLD}╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝  {G}║
║{C}        N E T W O R K   S C A N N E R             {G}║
╚{'═'*54}╝{RST}
{DIM}  [*] Apenas em redes com autorização.{RST}
""")

# ─── Gera lista de IPs a partir de CIDR ou range ──────────────────────────────
def generate_ip_list(target):
    ips = []
    if "/" in target:
        try:
            net = ipaddress.IPv4Network(target, strict=False)
            ips = [str(ip) for ip in net.hosts()]
        except:
            print(f"{R}[ERRO] CIDR inválido: {target}{RST}")
            sys.exit(1)
    elif "-" in target:
        # Formato: 192.168.1.1-192.168.1.50
        start_ip, end_ip = target.split("-")
        start = list(map(int, start_ip.strip().split(".")))
        end   = list(map(int, end_ip.strip().split(".")))
        # Assume que só o último octeto muda
        base  = start[:3]
        for i in range(start[3], end[3]+1):
            ips.append(f"{base[0]}.{base[1]}.{base[2]}.{i}")
    else:
        ips = [target]
    return ips

# ─── Resolução reversa de hostname ────────────────────────────────────────────
def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "N/A"

# ─── TTL → OS guess ───────────────────────────────────────────────────────────
def ttl_os_guess(ttl):
    if ttl is None: return "?"
    if ttl <= 64:  return "Linux/Unix"
    if ttl <= 128: return "Windows"
    if ttl <= 255: return "Cisco/Network"
    return "Desconhecido"

# ─── ICMP Ping ────────────────────────────────────────────────────────────────
def checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        if i+1 < len(data):
            s += (data[i] << 8) + data[i+1]
        else:
            s += data[i] << 8
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff

def build_icmp_packet(seq=1):
    # Type=8 (Echo Request), Code=0
    header = struct.pack("!BBHHH", 8, 0, 0, os.getpid() & 0xFFFF, seq)
    data   = b"cybersec_scanner"
    chk    = checksum(header + data)
    header = struct.pack("!BBHHH", 8, 0, chk, os.getpid() & 0xFFFF, seq)
    return header + data

def icmp_ping(ip, timeout=1.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.settimeout(timeout)
        packet = build_icmp_packet(random.randint(1, 65535))
        t_send = time.time()
        s.sendto(packet, (ip, 0))
        while True:
            data, addr = s.recvfrom(1024)
            t_recv = time.time()
            if addr[0] == ip:
                # Parse IP header para TTL
                ttl = data[8] if len(data) > 8 else None
                rtt = (t_recv - t_send) * 1000
                s.close()
                return True, ttl, round(rtt, 2)
    except:
        pass
    finally:
        try: s.close()
        except: pass
    return False, None, None

# ─── ARP Scan ─────────────────────────────────────────────────────────────────
def get_local_mac(iface="eth0"):
    """Obtém MAC da interface local via ioctl."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack("256s", iface[:15].encode()))
        return info[18:24]
    except:
        return b'\xff\xff\xff\xff\xff\xff'

def build_arp_request(src_mac, src_ip, dst_ip):
    """Constrói um frame Ethernet com ARP request."""
    # Ethernet header: dst_mac (broadcast), src_mac, ethertype 0x0806
    eth_dst  = b'\xff\xff\xff\xff\xff\xff'
    eth_type = b'\x08\x06'
    eth_hdr  = eth_dst + src_mac + eth_type

    # ARP payload
    htype    = b'\x00\x01'          # Hardware type: Ethernet
    ptype    = b'\x08\x00'          # Protocol type: IPv4
    hlen     = b'\x06'              # Hardware addr len
    plen     = b'\x04'              # Protocol addr len
    oper     = b'\x00\x01'          # Operation: REQUEST
    sha      = src_mac              # Sender hardware addr
    spa      = socket.inet_aton(src_ip)  # Sender protocol addr
    tha      = b'\x00'*6            # Target hardware addr (unknown)
    tpa      = socket.inet_aton(dst_ip)  # Target protocol addr

    arp      = htype + ptype + hlen + plen + oper + sha + spa + tha + tpa
    return eth_hdr + arp

def parse_arp_reply(frame):
    """Extrai MAC e IP do frame ARP reply."""
    if len(frame) < 42:
        return None, None
    eth_type = struct.unpack("!H", frame[12:14])[0]
    if eth_type != 0x0806:
        return None, None
    oper = struct.unpack("!H", frame[20:22])[0]
    if oper != 2:  # Reply
        return None, None
    src_mac_bytes = frame[22:28]
    src_ip_bytes  = frame[28:32]
    mac = ":".join(f"{b:02x}" for b in src_mac_bytes)
    ip  = socket.inet_ntoa(src_ip_bytes)
    return mac, ip

def arp_scan(ip_list, iface, timeout, src_ip, src_mac):
    """Envia ARP requests e coleta replies."""
    try:
        raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        raw_sock.bind((iface, 0))
    except Exception as e:
        print(f"{R}[ERRO ARP] {e} — tente como root ou use --method icmp{RST}")
        sys.exit(1)

    pending = set(ip_list)
    replies = {}

    # Thread de recepção
    def recv_loop():
        raw_sock.settimeout(timeout + 1)
        deadline = time.time() + timeout + 2
        while time.time() < deadline:
            try:
                frame, _ = raw_sock.recvfrom(65535)
                mac, ip  = parse_arp_reply(frame)
                if mac and ip and ip in pending:
                    replies[ip] = mac
            except:
                break

    recv_thread = threading.Thread(target=recv_loop, daemon=True)
    recv_thread.start()

    # Enviar ARP requests
    for ip in ip_list:
        pkt = build_arp_request(src_mac, src_ip, ip)
        try:
            raw_sock.send(pkt)
        except:
            pass
        time.sleep(0.002)  # Pequeno delay para não saturar

    recv_thread.join()
    raw_sock.close()
    return replies

# ─── Worker ICMP ──────────────────────────────────────────────────────────────
def icmp_worker(q, timeout):
    while not q.empty():
        try:
            ip = q.get_nowait()
        except:
            break
        alive, ttl, rtt = icmp_ping(ip, timeout)
        with lock:
            stats["sent"] += 1
            if alive:
                stats["alive"] += 1
                hostname = reverse_dns(ip)
                os_guess = ttl_os_guess(ttl)
                hosts[ip] = {"ttl": ttl, "rtt": rtt, "hostname": hostname, "os": os_guess}
                print(f"  {G}[VIVO]{RST} {W}{ip:<18}{RST} TTL:{Y}{ttl:<4}{RST} RTT:{C}{rtt}ms{RST}"
                      f" OS:{M}{os_guess:<14}{RST} {DIM}{hostname}{RST}")
        q.task_done()

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Advanced Network Scanner — Python puro")
    parser.add_argument("--range",   required=True, help="CIDR ou range: 192.168.1.0/24")
    parser.add_argument("--method",  default="icmp", help="Método: icmp, arp (arp=root+Linux)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout em segundos")
    parser.add_argument("--threads", type=int, default=100, help="Threads (modo ICMP)")
    parser.add_argument("--iface",   default="eth0", help="Interface (modo ARP)")
    parser.add_argument("--output",  default=None, help="Salvar resultado")
    args = parser.parse_args()

    ip_list = generate_ip_list(args.range)
    print(f"  {B}[*]{RST} Range    : {args.range}")
    print(f"  {B}[*]{RST} Total IPs: {len(ip_list)}")
    print(f"  {B}[*]{RST} Método   : {args.method.upper()}")
    print(f"  {B}[*]{RST} Timeout  : {args.timeout}s")
    print(f"\n  {Y}[SCAN INICIADO]{RST} {datetime.now().strftime('%H:%M:%S')}\n")
    print(f"  {'─'*70}")

    t0 = time.time()

    if args.method == "arp":
        if not sys.platform.startswith("linux"):
            print(f"{R}[ERRO] ARP scan disponível apenas no Linux.{RST}")
            sys.exit(1)
        src_ip  = socket.gethostbyname(socket.gethostname())
        src_mac = get_local_mac(args.iface)
        print(f"  {B}[*]{RST} IP local : {src_ip}")
        print(f"  {B}[*]{RST} Interface: {args.iface}\n")

        replies = arp_scan(ip_list, args.iface, args.timeout, src_ip, src_mac)
        for ip, mac in replies.items():
            hostname = reverse_dns(ip)
            hosts[ip] = {"mac":mac,"hostname":hostname}
            print(f"  {G}[VIVO]{RST} {W}{ip:<18}{RST} MAC:{Y}{mac}{RST} {DIM}{hostname}{RST}")

    else:  # ICMP
        from queue import Queue
        q = Queue()
        for ip in ip_list: q.put(ip)

        threads_list = []
        for _ in range(min(args.threads, len(ip_list))):
            t = threading.Thread(target=icmp_worker, args=(q, args.timeout), daemon=True)
            t.start()
            threads_list.append(t)

        # Progress
        total = len(ip_list)
        while any(t.is_alive() for t in threads_list):
            done = stats["sent"]
            pct  = int((done/total)*40) if total else 40
            bar  = f"{G}{'█'*pct}{DIM}{'░'*(40-pct)}{RST}"
            print(f"\r  [{bar}] {done}/{total}", end="", flush=True)
            time.sleep(0.3)

        for t in threads_list: t.join()
        print(f"\r  [{G}{'█'*40}{RST}] {total}/{total} {G}✓{RST}    ")

    elapsed = time.time() - t0

    # Resumo
    print(f"\n{C}{'─'*60}{RST}")
    print(f"{BOLD}{W}  RESUMO{RST}")
    print(f"{C}{'─'*60}{RST}")
    print(f"  IPs verificados : {len(ip_list)}")
    print(f"  Hosts ativos    : {G}{len(hosts)}{RST}")
    print(f"  Tempo           : {elapsed:.2f}s")

    if hosts:
        print(f"\n  {BOLD}HOSTS ATIVOS:{RST}")
        for ip in sorted(hosts.keys(), key=lambda x: list(map(int, x.split(".")))):
            info = hosts[ip]
            extra = f"MAC:{info.get('mac','')} " if "mac" in info else \
                    f"TTL:{info.get('ttl','')} RTT:{info.get('rtt','')}ms OS:{info.get('os','')} "
            print(f"  {G}{ip:<18}{RST} {extra}{DIM}{info.get('hostname','')}{RST}")

    if args.output:
        with open(args.output,"w") as f:
            f.write(f"Network Scan — {datetime.now()}\n")
            f.write(f"Range: {args.range}\n")
            f.write(f"Ativos: {len(hosts)}/{len(ip_list)}\n\n")
            for ip, info in hosts.items():
                f.write(f"{ip} — {info}\n")
        print(f"\n  {G}[✓] Resultado salvo em: {args.output}{RST}")

if __name__ == "__main__":
    main()
