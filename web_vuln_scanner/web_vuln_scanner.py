#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║          WEB VULNERABILITY SCANNER v2                    ║
║  XSS | SQLi | LFI | Open Redirect | Headers | CSRF      ║
╚══════════════════════════════════════════════════════════╝
Uso:
  python3 web_vuln_scanner.py -u https://example.com
  python3 web_vuln_scanner.py -u https://example.com --checks xss,sqli,lfi
  python3 web_vuln_scanner.py -u https://example.com --crawl --depth 2 --output relatorio
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))
from common import *

import socket, ssl, urllib.parse, threading, argparse, re, time, random, struct
from queue    import Queue
from datetime import datetime
from html     import unescape

# ─── Payloads ─────────────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<svg onload=alert(1)>',
    '{{7*7}}',         # template injection probe
    '${7*7}',
]

SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR '1'='1' --",
    '" OR "1"="1',
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
    "1 UNION SELECT NULL--",
    "' AND SLEEP(2)--",
    "'; WAITFOR DELAY '0:0:2'--",
    "1' AND 1=CONVERT(int,@@version)--",
]

SQLI_ERRORS = [
    "sql syntax","mysql_fetch","ora-","pg_query","sqlite_","you have an error in your sql",
    "unclosed quotation","unterminated string","odbc driver","warning: pg_","microsoft ole db",
    "sqlstate","jdbc","syntax error","division by zero","invalid query",
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/passwd%00",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//....//etc/passwd",
    "../../../../windows/win.ini",
    "../../../../windows/system.ini",
    "/etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
]

LFI_SIGNATURES = [
    "root:x:0:0","daemon:","[extensions]","[fonts]","for 16-bit","php://",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "https:evil.com",
    "/\\evil.com",
]

SECURITY_HEADERS = [
    ("Strict-Transport-Security",  "MEDIUM", "HSTS ausente — força HTTP downgrade"),
    ("Content-Security-Policy",    "MEDIUM", "CSP ausente — facilita XSS"),
    ("X-Frame-Options",            "LOW",    "Clickjacking possível"),
    ("X-Content-Type-Options",     "LOW",    "MIME sniffing habilitado"),
    ("Referrer-Policy",            "LOW",    "Vazamento de referrer"),
    ("Permissions-Policy",         "INFO",   "Política de permissões ausente"),
    ("X-XSS-Protection",           "INFO",   "Header legado de XSS protection ausente"),
]

INTERESTING_PATHS = [
    "/.git/HEAD", "/.env", "/wp-config.php", "/config.php", "/admin/",
    "/robots.txt", "/sitemap.xml", "/.htaccess", "/backup.zip", "/backup.sql",
    "/phpinfo.php", "/info.php", "/server-status", "/actuator/health",
    "/api/v1/users", "/.DS_Store", "/crossdomain.xml", "/security.txt",
]

# ─── HTTP Client puro (sem requests) ─────────────────────────────────────────
class HTTPClient:
    def __init__(self, timeout=8, follow_redirects=True, max_redirects=5):
        self.timeout          = timeout
        self.follow_redirects = follow_redirects
        self.max_redirects    = max_redirects
        self.user_agent       = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

    def _parse_url(self, url):
        if not url.startswith("http"):
            url = "http://" + url
        p = urllib.parse.urlparse(url)
        scheme = p.scheme
        host   = p.hostname
        port   = p.port or (443 if scheme == "https" else 80)
        path   = p.path or "/"
        if p.query:
            path += "?" + p.query
        return scheme, host, port, path

    def _make_socket(self, scheme, host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect((socket.gethostbyname(host), port))
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        return s

    def request(self, method, url, headers=None, body=None, _redirects=0):
        try:
            scheme, host, port, path = self._parse_url(url)
            s = self._make_socket(scheme, host, port)

            hdrs = {
                "Host"           : host,
                "User-Agent"     : self.user_agent,
                "Accept"         : "*/*",
                "Accept-Language": "pt-BR,pt;q=0.9",
                "Connection"     : "close",
            }
            if headers:
                hdrs.update(headers)
            if body:
                hdrs["Content-Length"] = str(len(body.encode()))
                hdrs["Content-Type"]   = "application/x-www-form-urlencoded"

            req = f"{method} {path} HTTP/1.1\r\n"
            for k,v in hdrs.items():
                req += f"{k}: {v}\r\n"
            req += "\r\n"
            if body:
                req += body

            s.send(req.encode("utf-8", errors="ignore"))

            raw = b""
            while True:
                try:
                    chunk = s.recv(8192)
                    if not chunk:
                        break
                    raw += chunk
                    if len(raw) > 500_000:
                        break
                except:
                    break
            s.close()

            if b"\r\n\r\n" not in raw:
                return None

            header_part, body_part = raw.split(b"\r\n\r\n", 1)
            header_str = header_part.decode("utf-8", errors="ignore")
            lines       = header_str.split("\r\n")
            status_line = lines[0]
            status_code = int(status_line.split()[1]) if len(status_line.split()) > 1 else 0

            resp_headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    resp_headers[k.strip().lower()] = v.strip()

            # Decode body
            try:
                body_text = body_part.decode("utf-8", errors="ignore")
            except:
                body_text = ""

            # Follow redirect
            if self.follow_redirects and status_code in (301,302,303,307,308) and _redirects < self.max_redirects:
                loc = resp_headers.get("location","")
                if loc:
                    if loc.startswith("/"):
                        loc = f"{scheme}://{host}:{port}{loc}"
                    return self.request(method, loc, headers=headers, _redirects=_redirects+1)

            return {
                "status"  : status_code,
                "headers" : resp_headers,
                "body"    : body_text,
                "url"     : url,
            }
        except Exception as e:
            return None

    def get(self, url, headers=None):
        return self.request("GET", url, headers=headers)

    def post(self, url, body="", headers=None):
        return self.request("POST", url, headers=headers, body=body)


# ─── Crawler simples ──────────────────────────────────────────────────────────
def crawl(base_url, client, max_depth=2, max_pages=50):
    """Extrai links e formulários do site."""
    visited  = set()
    to_visit = [(base_url, 0)]
    pages    = {}   # url → {forms, params, links}

    parsed_base = urllib.parse.urlparse(base_url)
    base_host   = parsed_base.hostname

    while to_visit and len(visited) < max_pages:
        url, depth = to_visit.pop(0)
        if url in visited or depth > max_depth:
            continue
        visited.add(url)

        resp = client.get(url)
        if not resp or resp["status"] >= 400:
            continue

        body = resp["body"]
        info = {"forms": [], "params": [], "links": [], "url": url}

        # Extrair params da URL
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        info["params"] = list(qs.keys())

        # Extrair formulários
        form_re = re.findall(r'<form[^>]*action=["\']?([^"\'> ]*)["\']?[^>]*>(.*?)</form>',
                              body, re.DOTALL | re.IGNORECASE)
        for action, form_body in form_re:
            inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', form_body, re.IGNORECASE)
            method_m = re.search(r'method=["\']?(\w+)["\']?', form_body, re.IGNORECASE)
            method = method_m.group(1).upper() if method_m else "GET"
            full_action = urllib.parse.urljoin(url, action) if action else url
            info["forms"].append({"action": full_action, "method": method, "inputs": inputs})

        # Extrair links
        links = re.findall(r'href=["\']([^"\'#]+)["\']', body, re.IGNORECASE)
        for link in links:
            abs_link = urllib.parse.urljoin(url, link)
            if urllib.parse.urlparse(abs_link).hostname == base_host:
                info["links"].append(abs_link)
                if depth + 1 <= max_depth:
                    to_visit.append((abs_link, depth + 1))

        pages[url] = info

    return pages


# ─── Checks ───────────────────────────────────────────────────────────────────

def check_security_headers(client, url, reporter):
    print(f"  {B}[*]{RST} Verificando security headers...")
    resp = client.get(url)
    if not resp:
        return
    for header, sev, desc in SECURITY_HEADERS:
        if header.lower() not in resp["headers"]:
            reporter.add("Headers", sev, f"Header ausente: {header}", desc)
            print_finding(sev, "Header", f"{header} ausente")
        else:
            reporter.add("Headers", "INFO", f"Header presente: {header}",
                         resp["headers"][header.lower()])


def check_interesting_paths(client, base_url, reporter):
    print(f"\n  {B}[*]{RST} Verificando paths sensíveis ({len(INTERESTING_PATHS)} paths)...")
    parsed = urllib.parse.urlparse(base_url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    for path in INTERESTING_PATHS:
        url  = base + path
        resp = client.get(url)
        if resp and resp["status"] < 400:
            sev = "HIGH" if any(x in path for x in [".env","config","backup","phpinfo"]) else "MEDIUM"
            reporter.add("Exposure", sev, f"Path acessível: {path}",
                         f"Status: {resp['status']} | URL: {url}", {"status": resp["status"]})
            print_finding(sev, "Exposure", f"[{resp['status']}] {path}")


def check_xss(client, pages, reporter):
    print(f"\n  {B}[*]{RST} Testando XSS...")
    tested = 0

    for page_url, info in pages.items():
        # GET params
        for param in info["params"]:
            for payload in XSS_PAYLOADS[:5]:
                tested += 1
                qs  = urllib.parse.parse_qs(urllib.parse.urlparse(page_url).query)
                qs[param] = [payload]
                test_url = page_url.split("?")[0] + "?" + urllib.parse.urlencode(qs, doseq=True)
                resp = client.get(test_url)
                if resp and payload in resp["body"]:
                    reporter.add("XSS", "HIGH",
                                 f"XSS Refletido em GET param '{param}'",
                                 f"URL: {test_url}\nPayload: {payload}",
                                 {"url": test_url, "param": param, "payload": payload})
                    print_finding("HIGH", "XSS", f"Refletido em GET '{param}' — {test_url[:60]}")
                    break

        # Forms
        for form in info["forms"]:
            for inp in form["inputs"][:3]:
                for payload in XSS_PAYLOADS[:4]:
                    tested += 1
                    data = "&".join(f"{i}={urllib.parse.quote(payload)}" for i in form["inputs"])
                    if form["method"] == "POST":
                        resp = client.post(form["action"], body=data)
                    else:
                        resp = client.get(form["action"] + "?" + data)
                    if resp and payload in (resp["body"] or ""):
                        reporter.add("XSS", "HIGH",
                                     f"XSS Refletido em form input '{inp}'",
                                     f"Action: {form['action']}\nPayload: {payload}")
                        print_finding("HIGH", "XSS", f"Form input '{inp}' — {form['action'][:60]}")
                        break

    if tested == 0:
        reporter.add("XSS", "INFO", "Nenhum parâmetro testável encontrado")
    print(f"  {DIM}XSS: {tested} testes realizados{RST}")


def check_sqli(client, pages, reporter):
    print(f"\n  {B}[*]{RST} Testando SQL Injection...")
    tested = 0

    for page_url, info in pages.items():
        for param in info["params"]:
            for payload in SQLI_PAYLOADS[:6]:
                tested += 1
                qs  = urllib.parse.parse_qs(urllib.parse.urlparse(page_url).query)
                qs[param] = [payload]
                test_url = page_url.split("?")[0] + "?" + urllib.parse.urlencode(qs, doseq=True)
                t0   = time.time()
                resp = client.get(test_url)
                elapsed = time.time() - t0

                if not resp:
                    continue

                body_lower = resp["body"].lower()

                # Error-based
                for err in SQLI_ERRORS:
                    if err in body_lower:
                        reporter.add("SQLi", "CRITICAL",
                                     f"SQL Injection (error-based) em '{param}'",
                                     f"URL: {test_url}\nPayload: {payload}\nErro detectado: {err}",
                                     {"url": test_url, "param": param, "payload": payload, "error": err})
                        print_finding("CRITICAL", "SQLi", f"Error-based em '{param}' — {test_url[:55]}")
                        break

                # Time-based (delay >= 1.8s)
                if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper():
                    if elapsed >= 1.8:
                        reporter.add("SQLi", "HIGH",
                                     f"SQL Injection (time-based) em '{param}'",
                                     f"URL: {test_url}\nPayload: {payload}\nDelay: {elapsed:.2f}s",
                                     {"url": test_url, "param": param, "delay": elapsed})
                        print_finding("HIGH", "SQLi", f"Time-based em '{param}' ({elapsed:.2f}s)")

    if tested == 0:
        reporter.add("SQLi", "INFO", "Nenhum parâmetro GET testável encontrado")
    print(f"  {DIM}SQLi: {tested} testes realizados{RST}")


def check_lfi(client, pages, reporter):
    print(f"\n  {B}[*]{RST} Testando LFI (Local File Inclusion)...")
    tested = 0

    for page_url, info in pages.items():
        for param in info["params"]:
            for payload in LFI_PAYLOADS:
                tested += 1
                qs  = urllib.parse.parse_qs(urllib.parse.urlparse(page_url).query)
                qs[param] = [payload]
                test_url = page_url.split("?")[0] + "?" + urllib.parse.urlencode(qs, doseq=True)
                resp = client.get(test_url)
                if not resp:
                    continue
                for sig in LFI_SIGNATURES:
                    if sig in resp["body"]:
                        reporter.add("LFI", "CRITICAL",
                                     f"Local File Inclusion em '{param}'",
                                     f"URL: {test_url}\nPayload: {payload}\nAssinatura: {sig}",
                                     {"url": test_url, "param": param, "payload": payload})
                        print_finding("CRITICAL", "LFI", f"Em '{param}' — payload: {payload}")
                        break

    if tested == 0:
        reporter.add("LFI", "INFO", "Nenhum parâmetro testável encontrado")
    print(f"  {DIM}LFI: {tested} testes realizados{RST}")


def check_open_redirect(client, pages, reporter):
    print(f"\n  {B}[*]{RST} Testando Open Redirect...")
    redirect_params = ["redirect","url","next","return","returnUrl","goto","dest","destination","forward","redir","r"]

    for page_url, info in pages.items():
        for param in info["params"]:
            if param.lower() not in redirect_params:
                continue
            for payload in OPEN_REDIRECT_PAYLOADS:
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(page_url).query)
                qs[param] = [payload]
                test_url = page_url.split("?")[0] + "?" + urllib.parse.urlencode(qs, doseq=True)
                resp = client.get(test_url)
                if resp and resp["status"] in (301,302,303,307,308):
                    loc = resp["headers"].get("location","")
                    if "evil.com" in loc:
                        reporter.add("Open Redirect", "MEDIUM",
                                     f"Open Redirect em '{param}'",
                                     f"URL: {test_url}\nLocation: {loc}")
                        print_finding("MEDIUM", "Redirect", f"'{param}' redireciona para: {loc}")


def check_csrf(client, pages, reporter):
    print(f"\n  {B}[*]{RST} Verificando proteção CSRF em formulários...")
    csrf_tokens = ["csrf","_token","authenticity_token","csrfmiddlewaretoken","__requestverificationtoken"]

    for page_url, info in pages.items():
        for form in info["forms"]:
            if form["method"] != "POST":
                continue
            has_token = any(i.lower() in csrf_tokens for i in form["inputs"])
            if not has_token:
                reporter.add("CSRF", "MEDIUM",
                             f"Form POST sem token CSRF",
                             f"Action: {form['action']}\nInputs: {form['inputs']}")
                print_finding("MEDIUM", "CSRF", f"Form sem token — {form['action'][:60]}")


def check_cors(client, url, reporter):
    print(f"\n  {B}[*]{RST} Verificando CORS...")
    resp = client.get(url, headers={"Origin": "https://evil.com"})
    if not resp:
        return
    acao = resp["headers"].get("access-control-allow-origin","")
    if acao == "*":
        reporter.add("CORS", "MEDIUM",
                     "CORS wildcard (*) — qualquer origem aceita",
                     f"Access-Control-Allow-Origin: {acao}")
        print_finding("MEDIUM", "CORS", "Wildcard (*) — qualquer origem aceita")
    elif "evil.com" in acao:
        reporter.add("CORS", "HIGH",
                     "CORS reflete origem arbitrária",
                     f"Access-Control-Allow-Origin: {acao}")
        print_finding("HIGH", "CORS", f"Origem refletida: {acao}")
    else:
        reporter.add("CORS", "INFO", f"CORS configurado: '{acao or 'não configurado'}'")


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    print_header(
        "WEB VULNERABILITY SCANNER v2",
        "XSS | SQLi | LFI | Open Redirect | Headers | CSRF | CORS",
        color=R
    )

    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner — Python puro")
    parser.add_argument("-u","--url",      required=True, help="URL alvo (ex: https://example.com)")
    parser.add_argument("--checks",        default="all",
                        help="Checks: all | xss,sqli,lfi,headers,paths,redirect,csrf,cors")
    parser.add_argument("--crawl",         action="store_true", help="Crawl automático do site")
    parser.add_argument("--depth",         type=int, default=1, help="Profundidade do crawl")
    parser.add_argument("--timeout",       type=float, default=8, help="Timeout HTTP")
    parser.add_argument("--output",        default=None, help="Base do arquivo de saída (sem extensão)")
    args = parser.parse_args()

    url = args.url
    if not url.startswith("http"):
        url = "http://" + url

    checks = args.checks.lower()
    run_all = checks == "all"
    active  = set(checks.split(",")) if not run_all else set()

    print(f"  {B}[*]{RST} Alvo    : {W}{url}{RST}")
    print(f"  {B}[*]{RST} Checks  : {checks}")
    print(f"  {B}[*]{RST} Crawl   : {'Sim (depth=' + str(args.depth) + ')' if args.crawl else 'Não'}")
    print(f"  {B}[*]{RST} Início  : {datetime.now().strftime('%H:%M:%S')}\n")
    print(f"  {C}{'─'*60}{RST}")

    client   = HTTPClient(timeout=args.timeout)
    reporter = Reporter("Web Vulnerability Scanner", url)

    # Resolve IP
    try:
        parsed = urllib.parse.urlparse(url)
        ip = socket.gethostbyname(parsed.hostname)
        reporter.set_meta("IP", ip)
        reporter.set_meta("Host", parsed.hostname)
    except:
        pass

    # Crawl
    if args.crawl:
        print(f"  {Y}[CRAWL]{RST} Mapeando site (depth={args.depth})...")
        pages = crawl(url, client, max_depth=args.depth, max_pages=30)
        print(f"  {DIM}Páginas mapeadas: {len(pages)}{RST}\n")
    else:
        # Apenas a URL base com seus params
        resp_base = client.get(url)
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        info = {
            "forms" : [],
            "params": list(qs.keys()),
            "links" : [],
            "url"   : url,
        }
        if resp_base:
            form_re = re.findall(
                r'<form[^>]*action=["\']?([^"\'> ]*)["\']?[^>]*>(.*?)</form>',
                resp_base["body"], re.DOTALL | re.IGNORECASE)
            for action, form_body in form_re:
                inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', form_body, re.IGNORECASE)
                method_m = re.search(r'method=["\']?(\w+)["\']?', form_body, re.IGNORECASE)
                method   = method_m.group(1).upper() if method_m else "GET"
                full_act = urllib.parse.urljoin(url, action) if action else url
                info["forms"].append({"action": full_act, "method": method, "inputs": inputs})
        pages = {url: info}

    reporter.set_meta("Páginas analisadas", len(pages))
    reporter.set_meta("Parâmetros encontrados", sum(len(p["params"]) for p in pages.values()))
    reporter.set_meta("Formulários encontrados", sum(len(p["forms"])  for p in pages.values()))

    # ── Rodar checks ──
    if run_all or "headers" in active:
        check_security_headers(client, url, reporter)
    if run_all or "paths" in active:
        check_interesting_paths(client, url, reporter)
    if run_all or "cors" in active:
        check_cors(client, url, reporter)
    if run_all or "xss" in active:
        check_xss(client, pages, reporter)
    if run_all or "sqli" in active:
        check_sqli(client, pages, reporter)
    if run_all or "lfi" in active:
        check_lfi(client, pages, reporter)
    if run_all or "redirect" in active:
        check_open_redirect(client, pages, reporter)
    if run_all or "csrf" in active:
        check_csrf(client, pages, reporter)

    # ── Resumo ──
    sev_counts = {}
    for f in reporter.findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    print(f"\n{C}{'═'*62}{RST}")
    print(f"{BOLD}  RESUMO{RST}")
    print(f"{C}{'═'*62}{RST}")
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        cnt = sev_counts.get(sev, 0)
        if cnt:
            sc = severity_color(sev)
            print(f"  {sc}{sev:<10}{RST} {cnt} finding(s)")

    if args.output:
        reporter.save_all(args.output)
    else:
        print(f"\n  {DIM}Use --output <base> para salvar relatório TXT/JSON/HTML{RST}")

if __name__ == "__main__":
    main()
