#!/usr/bin/env python3
"""
╔══════════════════════════════════════════╗
║         ADVANCED PACKET SNIFFER          ║
║   Python puro | Raw Sockets | Filtros    ║
╚══════════════════════════════════════════╝
Uso (requer root/admin):
  sudo python3 packet_sniffer.py
  sudo python3 packet_sniffer.py --filter tcp --port 80
  sudo python3 packet_sniffer.py --filter icmp --verbose
  sudo python3 packet_sniffer.py --output captura.pcap-like
"""

import socket
import struct
import sys
import time
import argparse
import os
import threading
from datetime import datetime

# ─── Cores ANSI ───────────────────────────────────────────────────────────────
R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
M="\033[95m"; C="\033[96m"; W="\033[97m"; DIM="\033[2m"; RST="\033[0m"; BOLD="\033[1m"

PROTOCOLS = {1:"ICMP", 6:"TCP", 17:"UDP", 2:"IGMP", 89:"OSPF", 47:"GRE"}
TCP_FLAGS  = {0x01:"FIN",0x02:"SYN",0x04:"RST",0x08:"PSH",0x10:"ACK",0x20:"URG"}
HTTP_METHODS = [b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS "]

stats = {"pkts":0,"tcp":0,"udp":0,"icmp":0,"other":0,"bytes":0}
lock  = threading.Lock()

# ─── Banner ───────────────────────────────────────────────────────────────────
def print_banner():
    print(f"""
{M}╔{'═'*54}╗
║  {W}{BOLD}  ____  _   _ ___ _____  _____ _____ ____             {M}║
║  {W}{BOLD} / ___|| \\ | |_ _|  ___||  ___| ____|  _ \\            {M}║
║  {W}{BOLD} \\___ \\|  \\| || || |_   | |_  |  _| | |_) |           {M}║
║  {W}{BOLD}  ___) | |\\  || ||  _|  |  _| | |___|  _ <            {M}║
║  {W}{BOLD} |____/|_| \\_|___|_|    |_|   |_____|_| \\_\\           {M}║
║{C}           P A C K E T   S N I F F E R                {M}║
╚{'═'*54}╝{RST}
{DIM}  [*] Requer privilégios root. Apenas redes autorizadas.{RST}
""")

# ─── Parse Ethernet Header ────────────────────────────────────────────────────
def parse_ethernet(data):
    if len(data) < 14:
        return None
    dst = ":".join(f"{b:02x}" for b in data[0:6])
    src = ":".join(f"{b:02x}" for b in data[6:12])
    proto = struct.unpack("!H", data[12:14])[0]
    return dst, src, proto, data[14:]

# ─── Parse IPv4 Header ────────────────────────────────────────────────────────
def parse_ipv4(data):
    if len(data) < 20:
        return None
    ihl = (data[0] & 0x0F) * 4
    ttl, proto = data[8], data[9]
    src = socket.inet_ntoa(data[12:16])
    dst = socket.inet_ntoa(data[16:20])
    return {"src":src, "dst":dst, "proto":proto, "ttl":ttl, "ihl":ihl, "payload":data[ihl:]}

# ─── Parse TCP Header ─────────────────────────────────────────────────────────
def parse_tcp(data):
    if len(data) < 20:
        return None
    src_port, dst_port, seq, ack = struct.unpack("!HHLL", data[0:12])
    offset = ((data[12] >> 4) * 4)
    flags_byte = data[13]
    flags = [name for bit, name in TCP_FLAGS.items() if flags_byte & bit]
    payload = data[offset:]
    return {"src_port":src_port,"dst_port":dst_port,"seq":seq,"ack":ack,
            "flags":flags,"offset":offset,"payload":payload}

# ─── Parse UDP Header ─────────────────────────────────────────────────────────
def parse_udp(data):
    if len(data) < 8:
        return None
    src_port, dst_port, length = struct.unpack("!HHH", data[0:6])
    return {"src_port":src_port,"dst_port":dst_port,"length":length,"payload":data[8:]}

# ─── Parse ICMP ───────────────────────────────────────────────────────────────
def parse_icmp(data):
    if len(data) < 4:
        return None
    icmp_type, code = data[0], data[1]
    types = {0:"Echo Reply",3:"Dest Unreachable",8:"Echo Request",11:"TTL Exceeded"}
    return {"type":icmp_type,"code":code,"name":types.get(icmp_type,"Desconhecido")}

# ─── Detecta HTTP no payload ──────────────────────────────────────────────────
def detect_http(payload):
    if not payload:
        return None
    for method in HTTP_METHODS:
        if payload.startswith(method):
            try:
                lines = payload.decode("utf-8", errors="ignore").split("\r\n")
                return lines[0]  # Primeira linha HTTP
            except:
                return None
    # HTTP Response
    if payload.startswith(b"HTTP/"):
        try:
            return payload.decode("utf-8", errors="ignore").split("\r\n")[0]
        except:
            return None
    return None

# ─── Detecta DNS no payload UDP ───────────────────────────────────────────────
def detect_dns(payload, port):
    if port not in (53, 5353) or len(payload) < 12:
        return None
    try:
        qr = (payload[2] >> 7) & 1
        qdcount = struct.unpack("!H", payload[4:6])[0]
        return f"{'RESPOSTA' if qr else 'QUERY'} ({qdcount} perguntas)"
    except:
        return None

# ─── Exibe payload em hex ─────────────────────────────────────────────────────
def hexdump(data, limit=64):
    data = data[:limit]
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part  = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"    {DIM}{i:04x}  {hex_part:<48}  {ascii_part}{RST}")
    return "\n".join(lines)

# ─── Exibe pacote ─────────────────────────────────────────────────────────────
def display_packet(ip, transport, proto_name, verbose, port_filter):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    if proto_name == "TCP" and transport:
        src_p = transport["src_port"]
        dst_p = transport["dst_port"]
        flags = "+".join(transport["flags"]) or "-"

        if port_filter and src_p != port_filter and dst_p != port_filter:
            return

        http = detect_http(transport["payload"])
        color = G if "SYN" in transport["flags"] else (R if "RST" in transport["flags"] else W)
        print(f"{DIM}{ts}{RST} {B}TCP{RST} {color}{ip['src']}{RST}:{Y}{src_p}{RST}"
              f" → {color}{ip['dst']}{RST}:{Y}{dst_p}{RST} "
              f"[{M}{flags}{RST}] TTL:{ip['ttl']}")
        if http:
            print(f"  {G}↳ HTTP: {http}{RST}")
        if verbose and transport["payload"]:
            print(hexdump(transport["payload"]))

    elif proto_name == "UDP" and transport:
        src_p = transport["src_port"]
        dst_p = transport["dst_port"]

        if port_filter and src_p != port_filter and dst_p != port_filter:
            return

        dns = detect_dns(transport["payload"], dst_p)
        print(f"{DIM}{ts}{RST} {C}UDP{RST} {W}{ip['src']}{RST}:{Y}{src_p}{RST}"
              f" → {W}{ip['dst']}{RST}:{Y}{dst_p}{RST} len:{transport['length']}")
        if dns:
            print(f"  {C}↳ DNS: {dns}{RST}")

    elif proto_name == "ICMP" and transport:
        print(f"{DIM}{ts}{RST} {Y}ICMP{RST} {W}{ip['src']}{RST}"
              f" → {W}{ip['dst']}{RST} [{transport['name']}] code:{transport['code']}")

    else:
        if not port_filter:
            print(f"{DIM}{ts}{RST} {DIM}{proto_name}{RST} {ip['src']} → {ip['dst']}")

# ─── Thread de estatísticas ───────────────────────────────────────────────────
def stats_thread():
    while True:
        time.sleep(10)
        with lock:
            print(f"\n{DIM}  ── Stats: pkts={stats['pkts']} tcp={stats['tcp']} "
                  f"udp={stats['udp']} icmp={stats['icmp']} "
                  f"bytes={stats['bytes']/1024:.1f}KB ──{RST}\n")

# ─── Main sniffer loop ────────────────────────────────────────────────────────
def sniff(proto_filter, port_filter, verbose, output_file):
    try:
        # AF_PACKET = Linux; no Windows usar socket.AF_INET + IPPROTO_IP + SIO_RCVALL
        if sys.platform.startswith("linux"):
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((socket.gethostbyname(socket.gethostname()), 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except PermissionError:
        print(f"{R}[ERRO] Execute como root/administrador!{RST}")
        sys.exit(1)

    out_f = open(output_file, "w") if output_file else None

    print(f"  {G}[*]{RST} Sniffing iniciado — {datetime.now().strftime('%H:%M:%S')}")
    print(f"  {G}[*]{RST} Filtro protocolo : {proto_filter or 'TODOS'}")
    print(f"  {G}[*]{RST} Filtro porta     : {port_filter or 'TODAS'}")
    print(f"  {G}[*]{RST} Verbose          : {'Sim' if verbose else 'Não'}")
    print(f"  {G}[*]{RST} Pressione Ctrl+C para parar\n")
    print(f"  {'─'*70}")

    # Inicia thread de stats
    t = threading.Thread(target=stats_thread, daemon=True)
    t.start()

    try:
        while True:
            raw, addr = s.recvfrom(65535)

            with lock:
                stats["pkts"]  += 1
                stats["bytes"] += len(raw)

            # Em Linux temos Ethernet header
            if sys.platform.startswith("linux"):
                eth = parse_ethernet(raw)
                if not eth or eth[2] != 0x0800:  # Só IPv4
                    continue
                ip_data = eth[3]
            else:
                ip_data = raw

            ip = parse_ipv4(ip_data)
            if not ip:
                continue

            proto_name = PROTOCOLS.get(ip["proto"], f"PROTO:{ip['proto']}")
            transport  = None

            if ip["proto"] == 6:   # TCP
                with lock: stats["tcp"] += 1
                transport = parse_tcp(ip["payload"])
                if proto_filter and proto_filter.upper() != "TCP":
                    continue
            elif ip["proto"] == 17: # UDP
                with lock: stats["udp"] += 1
                transport = parse_udp(ip["payload"])
                if proto_filter and proto_filter.upper() != "UDP":
                    continue
            elif ip["proto"] == 1:  # ICMP
                with lock: stats["icmp"] += 1
                transport = parse_icmp(ip["payload"])
                if proto_filter and proto_filter.upper() != "ICMP":
                    continue
            else:
                with lock: stats["other"] += 1
                if proto_filter:
                    continue

            display_packet(ip, transport, proto_name, verbose, port_filter)

            if out_f:
                out_f.write(f"{datetime.now()} {proto_name} {ip['src']} -> {ip['dst']}\n")

    except KeyboardInterrupt:
        print(f"\n\n{Y}[!] Sniffing interrompido pelo usuário.{RST}")
        print(f"  Total pacotes : {stats['pkts']}")
        print(f"  TCP/UDP/ICMP  : {stats['tcp']}/{stats['udp']}/{stats['icmp']}")
        print(f"  Bytes captur. : {stats['bytes']/1024:.2f} KB")
        if out_f:
            out_f.close()
            print(f"  {G}[✓] Log salvo em: {output_file}{RST}")

    finally:
        if sys.platform == "win32":
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        s.close()

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Advanced Packet Sniffer — Python puro")
    parser.add_argument("--filter",  default=None, help="Protocolo: tcp, udp, icmp")
    parser.add_argument("--port",    type=int, default=None, help="Filtrar por porta")
    parser.add_argument("--verbose", action="store_true", help="Exibir hexdump do payload")
    parser.add_argument("--output",  default=None, help="Salvar log em arquivo")
    args = parser.parse_args()

    sniff(args.filter, args.port, args.verbose, args.output)

if __name__ == "__main__":
    main()
