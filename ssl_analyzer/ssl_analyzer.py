#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║              SSL/TLS ANALYZER v2                         ║
║  Certificados | Cifras | Vulnerabilidades | HSTS | CT    ║
╚══════════════════════════════════════════════════════════╝
Uso:
  python3 ssl_analyzer.py -t example.com
  python3 ssl_analyzer.py -t example.com --port 8443 --output relatorio
  python3 ssl_analyzer.py -t example.com --full
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))
from common import *

import socket, ssl, struct, datetime as dt, argparse, threading, time, hashlib, base64
from datetime import datetime

# ─── Constantes ───────────────────────────────────────────────────────────────
WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "EXPORT", "NULL", "anon", "MD5",
    "IDEA", "SEED", "CAMELLIA128", "ADH", "AECDH",
}

PROTOCOL_SCORES = {
    ssl.TLSVersion.TLSv1   : ("TLS 1.0", "CRITICAL", "Protocolo obsoleto, vulnerável a BEAST/POODLE"),
    ssl.TLSVersion.TLSv1_1 : ("TLS 1.1", "HIGH",     "Protocolo obsoleto, desuso em 2021"),
    ssl.TLSVersion.TLSv1_2 : ("TLS 1.2", "INFO",     "Seguro, mas TLS 1.3 é preferível"),
    ssl.TLSVersion.TLSv1_3 : ("TLS 1.3", "INFO",     "Protocolo atual — excelente"),
}

# ─── Teste de versão TLS ──────────────────────────────────────────────────────
def test_tls_version(host, port, min_ver, max_ver, timeout=5):
    """Tenta conectar com versão TLS específica."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        ctx.minimum_version = min_ver
        ctx.maximum_version = max_ver
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((socket.gethostbyname(host), port))
        ss = ctx.wrap_socket(s, server_hostname=host)
        ver = ss.version()
        cipher = ss.cipher()
        ss.close()
        return True, ver, cipher
    except ssl.SSLError:
        return False, None, None
    except Exception:
        return False, None, None

# ─── Obter certificado completo ───────────────────────────────────────────────
def get_certificate(host, port, timeout=8):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        s   = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((socket.gethostbyname(host), port))
        ss  = ctx.wrap_socket(s, server_hostname=host)
        cert_bin  = ss.getpeercert(binary_form=True)
        cert_dict = ss.getpeercert(binary_form=False)
        cipher    = ss.cipher()
        proto     = ss.version()
        ss.close()
        return cert_dict, cert_bin, cipher, proto
    except Exception as e:
        return None, None, None, None

# ─── Parse SANs ───────────────────────────────────────────────────────────────
def get_sans(cert_dict):
    sans = []
    for tup in cert_dict.get("subjectAltName", []):
        if tup[0] == "DNS":
            sans.append(tup[1])
    return sans

# ─── Fingerprint do certificado ───────────────────────────────────────────────
def cert_fingerprint(cert_bin):
    if not cert_bin:
        return "", ""
    sha1   = hashlib.sha1(cert_bin).hexdigest().upper()
    sha256 = hashlib.sha256(cert_bin).hexdigest().upper()
    return ":".join(sha1[i:i+2] for i in range(0, len(sha1), 2)), \
           ":".join(sha256[i:i+2] for i in range(0, len(sha256), 2))

# ─── Verificação de validade ──────────────────────────────────────────────────
def check_cert_validity(cert_dict):
    issues = []
    try:
        not_after_str = cert_dict.get("notAfter","")
        not_before_str = cert_dict.get("notBefore","")

        # Parse data (formato: "Jan  1 00:00:00 2025 GMT")
        fmt = "%b %d %H:%M:%S %Y %Z"
        try:
            not_after  = dt.datetime.strptime(not_after_str,  fmt)
            not_before = dt.datetime.strptime(not_before_str, fmt)
        except:
            fmt2 = "%b  %d %H:%M:%S %Y %Z"
            not_after  = dt.datetime.strptime(not_after_str.replace("  "," "),  fmt)
            not_before = dt.datetime.strptime(not_before_str.replace("  "," "), fmt)

        now  = dt.datetime.utcnow()
        days_left = (not_after - now).days

        if now > not_after:
            issues.append(("CRITICAL", "Certificado EXPIRADO", f"Expirou em {not_after_str}"))
        elif days_left < 7:
            issues.append(("CRITICAL", "Certificado expira em menos de 7 dias", f"{days_left} dias restantes"))
        elif days_left < 30:
            issues.append(("HIGH", f"Certificado expira em {days_left} dias", not_after_str))
        elif days_left < 90:
            issues.append(("MEDIUM", f"Certificado expira em {days_left} dias", not_after_str))
        else:
            issues.append(("INFO", f"Certificado válido por {days_left} dias", not_after_str))

        if now < not_before:
            issues.append(("HIGH", "Certificado ainda não é válido", f"Válido a partir de: {not_before_str}"))

    except Exception as e:
        issues.append(("MEDIUM", "Não foi possível verificar validade", str(e)))

    return issues

# ─── Probe Heartbleed (TLS 1.0/1.1 heartbeat) ────────────────────────────────
def probe_heartbleed(host, port, timeout=5):
    """
    Tenta detectar Heartbleed (CVE-2014-0160).
    Envia um heartbeat malformado e verifica se a conexão aceita.
    Nota: detecção de presença do heartbeat extension, não exploração.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((socket.gethostbyname(host), port))

        # ClientHello com heartbeat extension
        hello = bytes([
            0x16, 0x03, 0x01,             # TLS Record: Handshake, TLS 1.0
            0x00, 0x31,                   # Length 49
            0x01,                         # ClientHello
            0x00, 0x00, 0x2d,             # Length 45
            0x03, 0x02,                   # TLS 1.1
        ] + list(bytes(32)) +             # Random (32 bytes)
        [0x00] +                          # Session ID length 0
        [0x00, 0x02, 0x00, 0x2f] +        # Cipher suites (AES128-SHA)
        [0x01, 0x00] +                    # Compression methods
        [0x00, 0x08,                      # Extensions length 8
         0x00, 0x0f,                      # Heartbeat extension type
         0x00, 0x01,                      # Extension data length 1
         0x01])                           # Mode: peer_allowed_to_send

        s.send(bytes(hello))
        s.settimeout(2)

        data = b""
        try:
            data = s.recv(1024)
        except:
            pass
        s.close()

        # Se recebeu ServerHello com heartbeat extension (type 0x0f em extensions)
        if b"\x0f" in data and len(data) > 30:
            return True   # Heartbeat extension aceita — potencialmente vulnerável
        return False
    except:
        return False

# ─── Testa cipher suites fracas ──────────────────────────────────────────────
def check_weak_ciphers(host, port, reporter):
    print(f"  {B}[*]{RST} Verificando cipher suites...")
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        s   = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((socket.gethostbyname(host), port))
        ss  = ctx.wrap_socket(s, server_hostname=host)
        # Ciphers disponíveis no cliente/servidor negociados
        all_ciphers = ctx.get_ciphers()
        neg_cipher  = ss.cipher()
        ss.close()

        negotiated = neg_cipher[0] if neg_cipher else ""
        print(f"  {G}[Cipher]{RST} Negociado: {W}{negotiated}{RST}")
        reporter.add("TLS", "INFO", f"Cipher negociado: {negotiated}")

        weak_found = []
        for c in all_ciphers:
            name = c.get("name","")
            for weak in WEAK_CIPHERS:
                if weak in name:
                    weak_found.append(name)
                    break

        if weak_found:
            reporter.add("TLS", "HIGH",
                         f"{len(weak_found)} cipher(s) fraco(s) suportado(s)",
                         "\n".join(weak_found[:10]))
            print_finding("HIGH", "Cipher", f"{len(weak_found)} ciphers fracos suportados")
            for c in weak_found[:5]:
                print(f"             {DIM}{c}{RST}")
        else:
            reporter.add("TLS", "INFO", "Nenhum cipher fraco detectado no cliente SSL padrão")

    except Exception as e:
        print(f"  {DIM}Cipher check: {e}{RST}")

# ─── Verificar HSTS ───────────────────────────────────────────────────────────
def check_hsts(host, port, reporter):
    import urllib.parse
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((socket.gethostbyname(host), port))
        ss = ctx.wrap_socket(s, server_hostname=host)
        req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        ss.send(req.encode())
        resp = b""
        while True:
            chunk = ss.recv(4096)
            if not chunk: break
            resp += chunk
        ss.close()
        hdrs = {}
        for line in resp.decode("utf-8", errors="ignore").split("\r\n")[1:]:
            if ":" in line:
                k,v = line.split(":",1)
                hdrs[k.strip().lower()] = v.strip()

        hsts = hdrs.get("strict-transport-security","")
        if not hsts:
            reporter.add("HSTS", "MEDIUM", "HSTS ausente",
                         "HTTP Strict Transport Security não configurado")
            print_finding("MEDIUM", "HSTS", "Header HSTS ausente")
        else:
            max_age = re.search(r'max-age=(\d+)', hsts)
            age_val = int(max_age.group(1)) if max_age else 0
            if age_val < 10_368_000:  # < 120 dias
                reporter.add("HSTS", "LOW",
                             f"HSTS max-age muito curto: {age_val}s",
                             f"Recomendado: ≥ 31536000 (1 ano). Atual: {hsts}")
                print_finding("LOW", "HSTS", f"max-age insuficiente: {age_val}s")
            else:
                reporter.add("HSTS", "INFO", f"HSTS configurado: {hsts}")
                print(f"  {G}[HSTS]{RST} {DIM}{hsts[:80]}{RST}")

            if "includeSubDomains" not in hsts:
                reporter.add("HSTS", "LOW", "HSTS sem includeSubDomains",
                             "Subdomínios não cobertos pelo HSTS")
            if "preload" in hsts:
                reporter.add("HSTS", "INFO", "HSTS preload configurado")
    except Exception as e:
        pass

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    print_header(
        "SSL/TLS ANALYZER v2",
        "Certificados | Versões | Cifras | HSTS | Heartbleed | Expiração",
        color=G
    )

    parser = argparse.ArgumentParser(description="SSL/TLS Analyzer — Python puro")
    parser.add_argument("-t","--target",  required=True, help="Host alvo")
    parser.add_argument("-p","--port",    type=int, default=443, help="Porta (padrão: 443)")
    parser.add_argument("--full",         action="store_true", help="Análise completa")
    parser.add_argument("--output",       default=None, help="Base do arquivo de saída")
    args = parser.parse_args()

    host     = args.target
    port     = args.port
    reporter = Reporter("SSL/TLS Analyzer", f"{host}:{port}")

    try:
        ip = socket.gethostbyname(host)
        reporter.set_meta("IP", ip)
    except:
        ip = host

    print(f"  {B}[*]{RST} Alvo   : {W}{host}:{port}{RST} ({ip})")
    print(f"  {B}[*]{RST} Início : {datetime.now().strftime('%H:%M:%S')}\n")
    print(f"  {C}{'─'*60}{RST}")

    # ── 1. Certificado ──
    print(f"  {Y}[CERT]{RST} Obtendo certificado...")
    cert_dict, cert_bin, cipher, proto = get_certificate(host, port)

    if not cert_dict:
        print(f"  {R}[!]{RST} Não foi possível obter certificado SSL.")
        reporter.add("TLS", "CRITICAL", "Conexão SSL falhou",
                     "Não foi possível estabelecer conexão TLS com o servidor")
        if args.output:
            reporter.save_all(args.output)
        return

    # Sujeito
    subject = dict(x[0] for x in cert_dict.get("subject",[]))
    issuer  = dict(x[0] for x in cert_dict.get("issuer", []))
    cn      = subject.get("commonName","N/A")
    org     = subject.get("organizationName","N/A")
    iss_cn  = issuer.get("commonName","N/A")
    iss_org = issuer.get("organizationName","N/A")
    sans    = get_sans(cert_dict)
    fp_sha1, fp_sha256 = cert_fingerprint(cert_bin)

    print(f"\n  {G}[Cert]{RST} CN       : {W}{cn}{RST}")
    print(f"  {G}[Cert]{RST} Org      : {org}")
    print(f"  {G}[Cert]{RST} Emissor  : {iss_cn} / {iss_org}")
    print(f"  {G}[Cert]{RST} SANs     : {len(sans)} domains")
    for s in sans[:10]:
        print(f"             {DIM}{s}{RST}")
    if len(sans) > 10:
        print(f"             {DIM}... e mais {len(sans)-10}{RST}")

    print(f"  {G}[Cert]{RST} SHA-256  : {DIM}{fp_sha256[:60]}...{RST}")

    reporter.set_meta("CN", cn)
    reporter.set_meta("Organização", org)
    reporter.set_meta("Emissor", iss_cn)
    reporter.set_meta("SANs", len(sans))
    reporter.set_meta("SHA256", fp_sha256)
    reporter.add("Certificate", "INFO", f"CN: {cn}", f"Org: {org}\nEmissor: {iss_cn}")
    reporter.add("Certificate", "INFO", f"{len(sans)} SANs",
                 "\n".join(sans[:20]))

    # Self-signed?
    if subject == issuer:
        reporter.add("Certificate", "HIGH", "Certificado auto-assinado",
                     "Certificados self-signed não são confiáveis por navegadores")
        print_finding("HIGH", "Cert", "Auto-assinado (self-signed)")

    # Wildcard?
    if cn.startswith("*"):
        reporter.add("Certificate", "LOW", f"Wildcard certificate: {cn}",
                     "Wildcards cobrem todos os subdomínios — risco maior se comprometido")
        print_finding("LOW", "Cert", f"Wildcard: {cn}")

    # Validade
    print(f"\n  {Y}[Validade]{RST}")
    for sev, title, detail in check_cert_validity(cert_dict):
        reporter.add("Certificate", sev, title, detail)
        print_finding(sev, "Validade", f"{title} — {detail}")

    # ── 2. Versões TLS ──
    print(f"\n  {Y}[Versões TLS]{RST}")
    version_tests = []
    try:
        # TLS 1.2
        ok12, ver12, _ = test_tls_version(host, port,
                                           ssl.TLSVersion.TLSv1_2,
                                           ssl.TLSVersion.TLSv1_2)
        version_tests.append(("TLS 1.2", ok12))
        if ok12:
            reporter.add("TLS", "INFO", "TLS 1.2 suportado")
            print(f"  {G}[+]{RST} TLS 1.2 suportado")
        else:
            print(f"  {DIM}[-] TLS 1.2 não suportado{RST}")
    except:
        pass

    try:
        ok13, ver13, _ = test_tls_version(host, port,
                                           ssl.TLSVersion.TLSv1_3,
                                           ssl.TLSVersion.TLSv1_3)
        version_tests.append(("TLS 1.3", ok13))
        if ok13:
            reporter.add("TLS", "INFO", "TLS 1.3 suportado")
            print(f"  {G}[+]{RST} TLS 1.3 suportado {G}(ótimo){RST}")
        else:
            reporter.add("TLS", "LOW", "TLS 1.3 não suportado",
                         "TLS 1.3 oferece melhor segurança e performance")
            print(f"  {Y}[-]{RST} TLS 1.3 não suportado")
    except:
        pass

    # TLS 1.0 / 1.1 (legado)
    for ver_name, min_v, max_v, sev in [
        ("TLS 1.1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1, "HIGH"),
        ("TLS 1.0", ssl.TLSVersion.TLSv1,   ssl.TLSVersion.TLSv1,   "CRITICAL"),
    ]:
        try:
            ok, _, _ = test_tls_version(host, port, min_v, max_v)
            if ok:
                reporter.add("TLS", sev, f"{ver_name} habilitado",
                             f"{ver_name} é obsoleto e vulnerável. Deve ser desabilitado.")
                print_finding(sev, "TLS", f"{ver_name} habilitado — deve ser desabilitado")
        except:
            pass

    # Protocolo negociado
    print(f"\n  {G}[Proto]{RST} Negociado: {W}{proto}{RST}")
    reporter.set_meta("Protocolo negociado", proto)

    # ── 3. Ciphers ──
    print(f"\n  {Y}[Ciphers]{RST}")
    check_weak_ciphers(host, port, reporter)

    # Cipher negociado
    if cipher:
        cipher_name, proto_name, bits = cipher
        print(f"  {G}[Cipher]{RST} Suite: {W}{cipher_name}{RST}")
        print(f"  {G}[Cipher]{RST} Bits : {bits}")
        reporter.set_meta("Cipher suite", cipher_name)
        reporter.set_meta("Key bits", str(bits))

        if bits and bits < 128:
            reporter.add("TLS", "HIGH", f"Chave fraca: {bits} bits",
                         "Recomendado: ≥ 128 bits")
            print_finding("HIGH", "Cipher", f"Chave fraca: {bits} bits")
        if "RC4" in cipher_name:
            reporter.add("TLS", "CRITICAL", "RC4 detectado",
                         "RC4 é inseguro — CVE-2013-2566, RFC 7465")
            print_finding("CRITICAL", "Cipher", "RC4 — criptografia insegura")

    # ── 4. HSTS ──
    print(f"\n  {Y}[HSTS]{RST}")
    check_hsts(host, port, reporter)

    # ── 5. Heartbleed ──
    if args.full:
        print(f"\n  {Y}[Heartbleed]{RST} Verificando CVE-2014-0160...")
        hl = probe_heartbleed(host, port)
        if hl:
            reporter.add("Vulnerability", "HIGH",
                         "Heartbeat extension aceita — possível CVE-2014-0160",
                         "Servidor aceita TLS Heartbeat. Verifique se o OpenSSL está atualizado.")
            print_finding("HIGH", "Heartbleed", "Heartbeat extension aceita — verifique versão OpenSSL")
        else:
            reporter.add("Vulnerability", "INFO", "Heartbleed: sem indicação de vulnerabilidade")
            print(f"  {G}[+]{RST} Heartbleed: sem indicação de vulnerabilidade")

    # ── Resumo ──
    sev_counts = {}
    for f in reporter.findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    print(f"\n{C}{'═'*62}{RST}")
    print(f"{BOLD}  RESUMO SSL/TLS — {host}:{port}{RST}")
    print(f"{C}{'═'*62}{RST}")
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        cnt = sev_counts.get(sev, 0)
        if cnt:
            sc = severity_color(sev)
            print(f"  {sc}{sev:<10}{RST} {cnt} finding(s)")

    if args.output:
        reporter.save_all(args.output)
    else:
        print(f"\n  {DIM}Use --output <base> para salvar TXT/JSON/HTML{RST}")

if __name__ == "__main__":
    main()
