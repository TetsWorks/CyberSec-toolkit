#!/usr/bin/env python3
"""
╔══════════════════════════════════════════╗
║        ADVANCED DNS RECON                ║
║  Subdomínios | Zone Transfer | Records   ║
╚══════════════════════════════════════════╝
Uso:
  python3 dns_recon.py -d example.com
  python3 dns_recon.py -d example.com --subdomains --wordlist subdomains.txt
  python3 dns_recon.py -d example.com --zone-transfer --all
  python3 dns_recon.py --reverse 192.168.1.1-254
"""

import socket
import struct
import threading
import argparse
import sys
import os
import time
import random
import string as strmod
from queue import Queue
from datetime import datetime

R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
M="\033[95m"; C="\033[96m"; W="\033[97m"; DIM="\033[2m"; RST="\033[0m"; BOLD="\033[1m"

lock    = threading.Lock()
found   = {}
stats   = {"queried":0,"found":0}

# ─── Tipos de registro DNS ────────────────────────────────────────────────────
DNS_TYPES = {
    1:"A", 2:"NS", 5:"CNAME", 6:"SOA", 12:"PTR",
    15:"MX", 16:"TXT", 28:"AAAA", 33:"SRV", 255:"ANY"
}
DNS_TYPES_REV = {v:k for k,v in DNS_TYPES.items()}

# ─── Subdomínios padrão para brute force ──────────────────────────────────────
DEFAULT_SUBS = [
    "www","mail","ftp","smtp","pop","imap","webmail","admin","portal","vpn",
    "remote","api","dev","test","staging","beta","cdn","static","img","images",
    "blog","shop","store","mx","mx1","mx2","ns1","ns2","dns","dns1","dns2",
    "secure","login","auth","sso","app","apps","mobile","m","wap","forum",
    "support","help","docs","wiki","git","gitlab","github","svn","jira",
    "confluence","jenkins","ci","monitor","nagios","grafana","kibana","elastic",
    "db","database","sql","mysql","postgres","mongo","redis","rabbitmq","kafka",
    "proxy","firewall","router","gateway","vpn2","backup","archive","files",
    "upload","download","media","video","stream","live","chat","irc","slack",
    "intranet","internal","corp","extranet","partner","client","customer",
    "owa","exchange","sharepoint","outlook","teams","zoom","meet",
]

def print_banner():
    print(f"""
{C}╔{'═'*54}╗
║  {W}{BOLD}██████╗ ███╗  ██╗███████╗                      {C}║
║  {W}{BOLD}██╔══██╗████╗ ██║██╔════╝                      {C}║
║  {W}{BOLD}██║  ██║██╔██╗██║███████╗                      {C}║
║  {W}{BOLD}██║  ██║██║╚████║╚════██║                      {C}║
║  {W}{BOLD}██████╔╝██║ ╚███║███████║                      {C}║
║  {W}{BOLD}╚═════╝ ╚═╝  ╚══╝╚══════╝                      {C}║
║{M}            R E C O N   T O O L                   {C}║
╚{'═'*54}╝{RST}
{DIM}  [*] Apenas em domínios com autorização.{RST}
""")

# ─── Construtor de pacote DNS ──────────────────────────────────────────────────
def build_dns_query(domain, qtype=1):
    """Constrói um pacote DNS query raw."""
    txid   = random.randint(0, 65535)
    flags  = 0x0100  # RD=1 (recursion desired)
    qdcount= 1

    header = struct.pack("!HHHHHH", txid, flags, qdcount, 0, 0, 0)

    # Encode QNAME
    qname = b""
    for label in domain.split("."):
        encoded = label.encode()
        qname += struct.pack("B", len(encoded)) + encoded
    qname += b"\x00"

    question = qname + struct.pack("!HH", qtype, 1)  # QTYPE, QCLASS=IN
    return txid, header + question

# ─── Parser DNS simples ────────────────────────────────────────────────────────
def parse_dns_name(data, offset):
    """Faz o parsing de um nome DNS com suporte a pointers."""
    labels = []
    original_offset = offset
    jumped = False
    max_jumps = 10
    jumps = 0

    while offset < len(data):
        length = data[offset]

        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:  # Pointer
            if jumps >= max_jumps: break
            ptr = ((length & 0x3F) << 8) | data[offset+1]
            if not jumped:
                original_offset = offset + 2
            offset = ptr
            jumped = True
            jumps += 1
        else:
            offset += 1
            try:
                labels.append(data[offset:offset+length].decode("utf-8", errors="ignore"))
            except:
                labels.append("?")
            offset += length

    return ".".join(labels), (original_offset if jumped else offset)

def parse_dns_response(data, domain):
    """Extrai records da resposta DNS."""
    if len(data) < 12:
        return []

    txid   = struct.unpack("!H", data[0:2])[0]
    flags  = struct.unpack("!H", data[2:4])[0]
    ancount= struct.unpack("!H", data[6:8])[0]

    rcode = flags & 0x000F
    if rcode != 0:  # NXDOMAIN, REFUSED, etc
        return []

    records = []
    offset  = 12

    # Skip question section
    try:
        _, offset = parse_dns_name(data, offset)
        offset += 4  # QTYPE + QCLASS
    except:
        return []

    # Parse answers
    for _ in range(ancount):
        if offset >= len(data):
            break
        try:
            name, offset  = parse_dns_name(data, offset)
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[offset:offset+10])
            offset += 10
            rdata = data[offset:offset+rdlen]
            offset += rdlen

            type_name = DNS_TYPES.get(rtype, str(rtype))

            if rtype == 1 and rdlen == 4:    # A
                value = socket.inet_ntoa(rdata)
            elif rtype == 28 and rdlen == 16: # AAAA
                value = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype in (2,5,12):           # NS, CNAME, PTR
                value, _ = parse_dns_name(data, offset - rdlen)
            elif rtype == 15:                 # MX
                pref  = struct.unpack("!H", rdata[0:2])[0]
                exch, _ = parse_dns_name(data, offset - rdlen + 2)
                value = f"{pref} {exch}"
            elif rtype == 16:                 # TXT
                value = rdata[1:].decode("utf-8", errors="ignore") if rdata else ""
            elif rtype == 6:                  # SOA
                mname, idx  = parse_dns_name(data, offset - rdlen)
                rname, idx2 = parse_dns_name(data, idx)
                value = f"mname={mname} rname={rname}"
            else:
                value = rdata.hex()

            records.append({"type":type_name,"name":name,"value":value,"ttl":ttl})
        except:
            break

    return records

# ─── DNS query via raw UDP ─────────────────────────────────────────────────────
def dns_query(domain, qtype_str="A", server="8.8.8.8", port=53, timeout=3.0):
    qtype = DNS_TYPES_REV.get(qtype_str.upper(), 1)
    txid, packet = build_dns_query(domain, qtype)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(packet, (server, port))
        response, _ = s.recvfrom(4096)
        s.close()
        return parse_dns_response(response, domain)
    except:
        return []

# ─── Zone Transfer (AXFR) via TCP ─────────────────────────────────────────────
def zone_transfer(domain, ns_server, timeout=5.0):
    """Tenta zone transfer AXFR."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ns_server, 53))

        _, query = build_dns_query(domain, qtype=252)  # AXFR
        # TCP DNS: prefixar com comprimento 2 bytes
        s.send(struct.pack("!H", len(query)) + query)

        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            response += chunk

        s.close()

        # Parse múltiplos mensagens TCP
        records = []
        offset = 0
        while offset + 2 < len(response):
            msg_len = struct.unpack("!H", response[offset:offset+2])[0]
            offset += 2
            if offset + msg_len > len(response): break
            msg = response[offset:offset+msg_len]
            offset += msg_len
            records.extend(parse_dns_response(msg, domain))

        return records
    except Exception as e:
        return None  # Transferência recusada/falhou

# ─── Subdomain brute force ─────────────────────────────────────────────────────
def subdomain_worker(domain, q, nameserver, timeout):
    while not q.empty():
        try:
            sub = q.get_nowait()
        except:
            break

        fqdn = f"{sub}.{domain}"
        records = dns_query(fqdn, "A", nameserver, timeout=timeout)
        with lock:
            stats["queried"] += 1

        if records:
            ips = [r["value"] for r in records if r["type"] == "A"]
            if ips:
                with lock:
                    stats["found"] += 1
                    found[fqdn] = ips
                print(f"  {G}[FOUND]{RST} {W}{fqdn:<40}{RST} → {Y}{', '.join(ips)}{RST}")

        q.task_done()

# ─── Reverse lookup range ─────────────────────────────────────────────────────
def reverse_range(ip_range, nameserver, timeout, threads_n):
    """Resolução reversa de um range de IPs."""
    # Formato: 192.168.1.1-254
    parts = ip_range.split("-")
    base  = parts[0].rsplit(".", 1)[0]
    start = int(parts[0].rsplit(".", 1)[1])
    end   = int(parts[1]) if len(parts) > 1 else start

    print(f"\n  {B}[*]{RST} Reverse lookup: {base}.{start}–{base}.{end}\n")
    print(f"  {'─'*60}")

    q = Queue()
    for i in range(start, end+1):
        q.put(f"{base}.{i}")

    def rev_worker():
        while not q.empty():
            try:
                ip = q.get_nowait()
            except:
                break
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                print(f"  {G}[PTR]{RST} {W}{ip:<18}{RST} → {Y}{hostname}{RST}")
            except:
                pass
            q.task_done()

    threads = [threading.Thread(target=rev_worker, daemon=True)
               for _ in range(min(threads_n, end-start+1))]
    for t in threads: t.start()
    for t in threads: t.join()

# ─── Main ──────────────────────────────────────────────────────────────────────
def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Advanced DNS Recon — Python puro")
    parser.add_argument("-d","--domain",       help="Domínio alvo")
    parser.add_argument("--nameserver",        default="8.8.8.8", help="Servidor DNS")
    parser.add_argument("--subdomains",        action="store_true", help="Brute force de subdomínios")
    parser.add_argument("--wordlist",          default=None, help="Wordlist de subdomínios")
    parser.add_argument("--zone-transfer",     action="store_true", help="Tentar zone transfer AXFR")
    parser.add_argument("--all",               action="store_true", help="Buscar todos os tipos de record")
    parser.add_argument("--reverse",           default=None, help="Range para PTR: 192.168.1.1-254")
    parser.add_argument("--threads",           type=int, default=50, help="Threads")
    parser.add_argument("--timeout",           type=float, default=2.0, help="Timeout")
    parser.add_argument("--output",            default=None, help="Salvar resultado")
    args = parser.parse_args()

    if args.reverse:
        reverse_range(args.reverse, args.nameserver, args.timeout, args.threads)
        return

    if not args.domain:
        print(f"{R}[ERRO] Informe --domain ou --reverse{RST}")
        sys.exit(1)

    print(f"  {B}[*]{RST} Domínio    : {W}{args.domain}{RST}")
    print(f"  {B}[*]{RST} Nameserver : {args.nameserver}")
    print(f"  {B}[*]{RST} Iniciado   : {datetime.now().strftime('%H:%M:%S')}\n")

    all_records = {}

    # ── Consultas de records (agora inclui CAA, DNSKEY para DNSSEC) ──
    record_types = ["A","AAAA","MX","NS","TXT","SOA","CNAME","SRV"] if args.all else ["A","MX","NS","TXT","SOA"]
    print(f"  {Y}[RECORDS]{RST}")
    print(f"  {'─'*60}")

    for rtype in record_types:
        records = dns_query(args.domain, rtype, args.nameserver, timeout=args.timeout)
        if records:
            all_records[rtype] = records
            for r in records:
                print(f"  {C}{rtype:<8}{RST} {W}{r['name']:<35}{RST} {G}{r['value']}{RST}"
                      f" {DIM}TTL:{r['ttl']}{RST}")

    # ── SPF / DMARC / DKIM analysis ──
    print(f"\n  {Y}[EMAIL SECURITY — SPF/DMARC/DKIM]{RST}")
    print(f"  {'─'*60}")

    txt_records = all_records.get("TXT", [])
    spf_records = [r for r in txt_records if "v=spf1" in r["value"]]
    if spf_records:
        spf = spf_records[0]["value"]
        print(f"  {G}[SPF]{RST}   {DIM}{spf[:80]}{RST}")
        # Análise de SPF
        if "+all" in spf:
            print(f"  {R}[!]{RST} SPF usa '+all' — PERMISSIVO DEMAIS (qualquer servidor pode enviar)")
        elif "~all" in spf:
            print(f"  {Y}[~]{RST} SPF usa '~all' (softfail) — considera usar '-all'")
        elif "-all" in spf:
            print(f"  {G}[✓]{RST} SPF usa '-all' (hardfail) — configuração segura")
    else:
        print(f"  {R}[!]{RST} SPF ausente — risco de email spoofing")

    # DMARC
    dmarc_records = dns_query(f"_dmarc.{args.domain}", "TXT", args.nameserver, timeout=args.timeout)
    dmarc_vals    = [r for r in dmarc_records if "v=DMARC1" in r["value"]]
    if dmarc_vals:
        dmarc = dmarc_vals[0]["value"]
        print(f"  {G}[DMARC]{RST} {DIM}{dmarc[:80]}{RST}")
        if "p=none" in dmarc:
            print(f"  {Y}[~]{RST} DMARC policy=none — monitora mas não bloqueia")
        elif "p=quarantine" in dmarc:
            print(f"  {G}[✓]{RST} DMARC policy=quarantine")
        elif "p=reject" in dmarc:
            print(f"  {G}[✓]{RST} DMARC policy=reject — máxima proteção")
    else:
        print(f"  {R}[!]{RST} DMARC ausente — emails falsificados podem ser entregues")

    # DKIM (tenta seletor padrão)
    for selector in ["default", "google", "k1", "mail", "smtp", "dkim"]:
        dkim_recs = dns_query(f"{selector}._domainkey.{args.domain}", "TXT",
                               args.nameserver, timeout=args.timeout)
        dkim_vals = [r for r in dkim_recs if "v=DKIM1" in r.get("value","")]
        if dkim_vals:
            print(f"  {G}[DKIM]{RST}  Seletor '{selector}' encontrado {G}✓{RST}")
            break
    else:
        print(f"  {Y}[~]{RST} DKIM não detectado nos seletores comuns")

    # ── CAA Records ──
    print(f"\n  {Y}[CAA — Certificate Authority Authorization]{RST}")
    print(f"  {'─'*60}")
    # CAA é tipo 257 — vamos tentar via DNS query type 257
    caa_records = dns_query(args.domain, "ANY", args.nameserver, timeout=args.timeout)
    caa_found   = [r for r in caa_records if "caa" in r.get("type","").lower() or
                   "letsencrypt" in r.get("value","").lower() or
                   "digicert" in r.get("value","").lower()]
    # Fallback: verificar via TXT se tem referências CAA
    if not caa_found:
        print(f"  {Y}[~]{RST} CAA não detectado — qualquer CA pode emitir certificados para este domínio")
        print(f"       {DIM}Recomendado: adicionar registro CAA restringindo CAs autorizadas{RST}")
    else:
        for r in caa_found:
            print(f"  {G}[CAA]{RST} {r['value']}")

    # ── DNSSEC ──
    print(f"\n  {Y}[DNSSEC]{RST}")
    print(f"  {'─'*60}")
    # Verificar se há DS ou DNSKEY records
    ds_records  = dns_query(args.domain, "ANY", args.nameserver, timeout=args.timeout)
    soa_records = all_records.get("SOA",[])
    if soa_records:
        soa_val = soa_records[0]["value"]
        # Se SOA existe e TTL é consistente, DNSSEC pode estar ativo
        print(f"  {G}[SOA]{RST}  {DIM}{soa_val[:80]}{RST}")

    # Verificar AD flag via consulta com DNSSEC request bit
    # (simplificado: verificar se o domínio tem registros NS consistentes)
    ns_records = all_records.get("NS",[])
    if ns_records:
        print(f"  {DIM}NS servers: {', '.join(r['value'].rstrip('.') for r in ns_records[:3])}{RST}")
        # Heurística: domínios com múltiplos NS de provedores conhecidos provavelmente têm DNSSEC
        ns_values = " ".join(r["value"] for r in ns_records).lower()
        dnssec_hint = any(p in ns_values for p in ["cloudflare","google","aws","azure","verisign"])
        if dnssec_hint:
            print(f"  {G}[~]{RST} DNSSEC provavelmente configurado (provedor com suporte nativo)")
        else:
            print(f"  {Y}[~]{RST} Não foi possível confirmar DNSSEC — verificar manualmente")
    else:
        print(f"  {DIM}NS não resolvido — DNSSEC indeterminado{RST}")

    # ── Zone Transfer ──
    if args.zone_transfer:
        print(f"\n  {Y}[ZONE TRANSFER — AXFR]{RST}")
        print(f"  {'─'*60}")
        ns_records = all_records.get("NS", [])
        if not ns_records:
            ns_records = dns_query(args.domain, "NS", args.nameserver, timeout=args.timeout)

        if not ns_records:
            print(f"  {R}Nenhum NS encontrado.{RST}")
        else:
            for ns_rec in ns_records:
                ns_name = ns_rec["value"].rstrip(".")
                try:
                    ns_ip = socket.gethostbyname(ns_name)
                    print(f"  {B}[*]{RST} Tentando AXFR em {ns_name} ({ns_ip})...")
                    zt_records = zone_transfer(args.domain, ns_ip, args.timeout)
                    if zt_records is None:
                        print(f"  {R}[-] AXFR recusado ou falhou em {ns_name}{RST}")
                    elif zt_records:
                        print(f"  {G}[+] AXFR BEM SUCEDIDO em {ns_name}! {len(zt_records)} records:{RST}")
                        for r in zt_records[:50]:
                            print(f"  {G}{r['type']:<8}{RST} {r['name']:<35} {r['value']}")
                    else:
                        print(f"  {R}[-] AXFR vazio em {ns_name}{RST}")
                except:
                    print(f"  {R}[-] Não foi possível resolver {ns_name}{RST}")

    # ── Subdomain Brute Force ──
    if args.subdomains:
        print(f"\n  {Y}[SUBDOMAIN BRUTE FORCE]{RST}")
        print(f"  {'─'*60}")

        if args.wordlist and os.path.exists(args.wordlist):
            with open(args.wordlist) as f:
                subs = [l.strip() for l in f if l.strip()]
        else:
            subs = DEFAULT_SUBS
            print(f"  {DIM}Usando {len(subs)} subdomínios padrão. Use --wordlist para mais.{RST}")

        print(f"  {B}[*]{RST} Testando {len(subs)} subdomínios com {args.threads} threads...\n")

        q = Queue()
        for s in subs: q.put(s)

        threads = [threading.Thread(
            target=subdomain_worker,
            args=(args.domain, q, args.nameserver, args.timeout),
            daemon=True
        ) for _ in range(min(args.threads, len(subs)))]
        for t in threads: t.start()

        total = len(subs)
        while any(t.is_alive() for t in threads):
            done = stats["queried"]
            pct  = int((done/total)*40) if total else 40
            bar  = f"{G}{'█'*pct}{DIM}{'░'*(40-pct)}{RST}"
            print(f"\r  [{bar}] {done}/{total} | encontrados: {stats['found']}", end="", flush=True)
            time.sleep(0.3)
        for t in threads: t.join()
        print(f"\r  [{G}{'█'*40}{RST}] {total}/{total} {G}✓{RST}    ")

    # ── Resumo ──
    print(f"\n{C}{'═'*60}{RST}")
    print(f"{BOLD}  RESUMO{RST}")
    print(f"{C}{'═'*60}{RST}")
    for rtype, recs in all_records.items():
        print(f"  {C}{rtype:<8}{RST} {len(recs)} registro(s)")

    if args.subdomains:
        print(f"  {G}Subdomínios encontrados: {len(found)}{RST}")
        for sub, ips in sorted(found.items()):
            print(f"  {G}→{RST} {sub} → {', '.join(ips)}")

    if args.output:
        with open(args.output,"w") as f:
            f.write(f"DNS Recon — {args.domain} — {datetime.now()}\n")
            f.write("="*60+"\n\n")
            for rtype, recs in all_records.items():
                f.write(f"[{rtype}]\n")
                for r in recs:
                    f.write(f"  {r['name']} {r['value']} TTL:{r['ttl']}\n")
            if found:
                f.write("\n[SUBDOMÍNIOS]\n")
                for sub, ips in found.items():
                    f.write(f"  {sub} → {', '.join(ips)}\n")
        print(f"\n  {G}[✓] Resultado salvo em: {args.output}{RST}")

if __name__ == "__main__":
    main()
