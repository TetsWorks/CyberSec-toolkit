#!/usr/bin/env python3
"""
╔══════════════════════════════════════════╗
║          ADVANCED HASH CRACKER           ║
║  Identify | Crack | Rainbow | Benchmark  ║
╚══════════════════════════════════════════╝
Uso:
  python3 hash_cracker.py --identify 5f4dcc3b5aa765d61d8327deb882cf99
  python3 hash_cracker.py --crack 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist rockyou.txt
  python3 hash_cracker.py --crack <hash> --brute --charset alphanum --max 5
  python3 hash_cracker.py --rainbow --algo md5 --size 100000 --output rainbow.db
  python3 hash_cracker.py --benchmark
"""

import hashlib
import hmac
import itertools
import threading
import argparse
import sys
import os
import time
import json
import struct
import base64
import binascii
import string
from queue import Queue
from datetime import datetime

R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
M="\033[95m"; C="\033[96m"; W="\033[97m"; DIM="\033[2m"; RST="\033[0m"; BOLD="\033[1m"

# ─── Algoritmos suportados ─────────────────────────────────────────────────────
ALGOS = {
    "md5"     : (hashlib.md5,     32,  "MD5"),
    "sha1"    : (hashlib.sha1,    40,  "SHA-1"),
    "sha224"  : (hashlib.sha224,  56,  "SHA-224"),
    "sha256"  : (hashlib.sha256,  64,  "SHA-256"),
    "sha384"  : (hashlib.sha384,  96,  "SHA-384"),
    "sha512"  : (hashlib.sha512,  128, "SHA-512"),
    "sha3_256": (hashlib.sha3_256,64,  "SHA3-256"),
    "sha3_512": (hashlib.sha3_512,128, "SHA3-512"),
    "blake2s" : (hashlib.blake2s, 64,  "BLAKE2s"),
    "blake2b" : (hashlib.blake2b, 128, "BLAKE2b"),
}

# ─── Hash especiais (não em ALGOS padrão) ─────────────────────────────────────
def do_ntlm(text):
    """NTLM hash (MD4 do UTF-16LE)."""
    import struct
    data = text.encode("utf-16-le")
    # MD4 implementado manualmente (não está em hashlib padrão)
    # Fallback: usar hashlib se disponível
    try:
        h = hashlib.new("md4")
        h.update(data)
        return h.hexdigest()
    except ValueError:
        # MD4 não disponível — implementação manual simplificada
        return _md4(data)

def _md4(msg):
    """MD4 puro Python (para NTLM quando openssl não tem md4)."""
    import struct
    def F(x,y,z): return (x&y)|((~x)&z)
    def G(x,y,z): return (x&y)|(x&z)|(y&z)
    def H(x,y,z): return x^y^z
    def rotl(x,n): return ((x<<n)|(x>>(32-n)))&0xFFFFFFFF

    msg = bytearray(msg)
    orig_len = len(msg)*8
    msg.append(0x80)
    while len(msg)%64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", orig_len)

    A,B,C,D = 0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476

    for i in range(0,len(msg),64):
        X = list(struct.unpack("<16I", msg[i:i+64]))
        a,b,c,d = A,B,C,D
        for j in [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]:
            a = rotl((a+F(b,c,d)+X[j])&0xFFFFFFFF, [3,7,11,19][j%4])
            a,b,c,d = d,a,b,c
        for j,k in [(0,3),(4,7),(8,11),(12,15)]:
            for l in range(j,k+1):
                a = rotl((a+G(b,c,d)+X[l]+0x5A827999)&0xFFFFFFFF, [3,5,9,13][l%4])
                a,b,c,d = d,a,b,c
        for j,k,order in [(0,3,0),(4,7,2),(8,11,1),(12,15,3)]:
            xidx = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15][j*4:k*4+4]
            for l in xidx:
                a = rotl((a+H(b,c,d)+X[l]+0x6ED9EBA1)&0xFFFFFFFF, [3,9,11,15][xidx.index(l)%4])
                a,b,c,d = d,a,b,c
        A=(A+a)&0xFFFFFFFF; B=(B+b)&0xFFFFFFFF
        C=(C+c)&0xFFFFFFFF; D=(D+d)&0xFFFFFFFF

    return struct.pack("<4I",A,B,C,D).hex()

def do_bcrypt_verify(password, hash_str):
    """Verifica senha contra hash bcrypt."""
    try:
        import bcrypt
        return bcrypt.checkpw(password.encode(), hash_str.encode())
    except ImportError:
        # Sem bcrypt instalado — avisa mas não trava
        return False

def do_scrypt(text, salt=b"", n=16384, r=8, p=1):
    """scrypt KDF."""
    try:
        return hashlib.scrypt(text.encode(), salt=salt, n=n, r=r, p=p, dklen=32).hex()
    except:
        return ""


CHARSETS = {
    "lower"  : string.ascii_lowercase,
    "upper"  : string.ascii_uppercase,
    "alpha"  : string.ascii_letters,
    "numeric": string.digits,
    "alphanum":string.ascii_letters + string.digits,
    "full"   : string.ascii_letters + string.digits + string.punctuation,
}

lock   = threading.Lock()
found  = threading.Event()
result = {"hash":"","plain":"","algo":""}
stats  = {"tried":0,"start":time.time()}

def print_banner():
    print(f"""
{M}╔{'═'*56}╗
║  {W}{BOLD}██╗  ██╗ █████╗ ███████╗██╗  ██╗                 {M}║
║  {W}{BOLD}██║  ██║██╔══██╗██╔════╝██║  ██║                 {M}║
║  {W}{BOLD}███████║███████║███████╗███████║                 {M}║
║  {W}{BOLD}██╔══██║██╔══██║╚════██║██╔══██║                 {M}║
║  {W}{BOLD}██║  ██║██║  ██║███████║██║  ██║                 {M}║
║  {W}{BOLD}╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝                 {M}║
║{C}             H A S H   C R A C K E R               {M}║
╚{'═'*56}╝{RST}
{DIM}  [*] Apenas para fins educacionais e hashes próprios.{RST}
""")

# ─── Hash de string ────────────────────────────────────────────────────────────
def do_hash(text, algo):
    if algo == "ntlm":
        return do_ntlm(text)
    if algo == "bcrypt":
        # Para bcrypt no crack mode, verificação é feita no worker
        return ""
    try:
        h = ALGOS[algo][0]()
        h.update(text.encode("utf-8", errors="ignore"))
        return h.hexdigest()
    except:
        return ""

# ─── Hash com salt ─────────────────────────────────────────────────────────────
def do_hash_salted(text, salt, algo, salt_position="prefix"):
    if salt_position == "prefix":
        data = salt + text
    else:
        data = text + salt
    return do_hash(data, algo)

# ─── IDENTIFICAÇÃO de hash ────────────────────────────────────────────────────
def identify_hash(h):
    h = h.strip()
    candidates = []

    # ── Formatos especiais com prefixo ──
    if h.startswith("$2a$") or h.startswith("$2b$") or h.startswith("$2y$"):
        return [("bcrypt", "Adaptive hash — muito seguro, não é crackeável por brute force rápido")]
    if h.startswith("$argon2"):
        return [("argon2", "State-of-the-art — requer argon2-cffi para verificar")]
    if h.startswith("$scrypt$"):
        return [("scrypt", "Key derivation function — lento por design")]
    if h.startswith("pbkdf2"):
        return [("pbkdf2", "Key derivation function")]
    if h.startswith("$1$"):
        return [("md5-crypt", "MD5 Unix crypt ($1$)")]
    if h.startswith("$5$"):
        return [("sha256-crypt", "SHA-256 Unix crypt ($5$)")]
    if h.startswith("$6$"):
        return [("sha512-crypt", "SHA-512 Unix crypt ($6$) — Linux /etc/shadow")]
    if h.startswith("$P$") or h.startswith("$H$"):
        return [("phpass", "WordPress / phpBB password hash")]

    hl = h.lower()
    is_hex = all(c in "0123456789abcdef" for c in hl)

    length_map = {
        32 : [("md5",""), ("ntlm","Windows NTLM — MD4 do UTF-16LE"), ("md4",""), ("lm","LAN Manager (muito fraco)")],
        40 : [("sha1",""), ("ripemd-160","")],
        48 : [("tiger-192","")],
        56 : [("sha224",""), ("sha3-224","")],
        64 : [("sha256",""), ("sha3_256",""), ("blake2s",""), ("ripemd-256","")],
        96 : [("sha384",""), ("sha3-384","")],
        128: [("sha512",""), ("sha3_512",""), ("blake2b",""), ("whirlpool","")],
    }

    candidates = length_map.get(len(hl), [(f"comprimento-{len(hl)}", "")])

    extra = []
    if is_hex: extra.append("hexadecimal")

    # Base64 check
    try:
        decoded = base64.b64decode(h + "==")
        if len(decoded)*2 in length_map:
            candidates.insert(0, (f"base64({length_map[len(decoded)*2][0][0]})", ""))
        extra.append("base64")
    except:
        pass

    return [(c[0], c[1] or "/".join(extra)) for c in candidates]


# ─── WORKER: Dictionary ───────────────────────────────────────────────────────
def dict_worker(target_hash, algo, q, salt, salt_pos, rules):
    while not found.is_set():
        try:
            word = q.get(timeout=0.5)
        except:
            break

        candidates = [word]
        if rules:
            candidates += list(generate_rules(word))

        for pwd in candidates:
            if found.is_set(): break

            # bcrypt usa verificação especial
            if algo == "bcrypt":
                matched = do_bcrypt_verify(pwd, target_hash)
            elif salt:
                h = do_hash_salted(pwd, salt, algo, salt_pos)
                matched = (h == target_hash)
            else:
                h = do_hash(pwd, algo)
                matched = (h == target_hash)

            with lock:
                stats["tried"] += 1

            if matched:
                with lock:
                    result["hash"]  = target_hash
                    result["plain"] = pwd
                    result["algo"]  = algo
                found.set()
                break

        q.task_done()


# ─── Regras de mutação ─────────────────────────────────────────────────────────
def generate_rules(word):
    variants = set()
    variants.add(word.capitalize())
    variants.add(word.upper())
    variants.add(word[::-1])  # Reverse
    variants.add(word + "!")
    variants.add(word + "123")
    variants.add(word + "1234")
    variants.add(word + "2024")
    variants.add(word + "2025")
    variants.add("!" + word)
    # L33t
    leet = word.lower()
    for a,b in [("a","@"),("e","3"),("i","1"),("o","0"),("s","$"),("t","7")]:
        leet = leet.replace(a,b)
    variants.add(leet)
    # Double
    variants.add(word * 2)
    return variants - {word}

# ─── WORKER: Brute Force ──────────────────────────────────────────────────────
def brute_worker(target_hash, algo, q, salt, salt_pos):
    local_count = 0
    while True:
        try:
            pwd = q.get(timeout=0.5)
        except:
            break

        h = do_hash_salted(pwd, salt, algo, salt_pos) if salt else do_hash(pwd, algo)
        local_count += 1

        if local_count % 1000 == 0:
            with lock:
                stats["tried"] += local_count
            local_count = 0

        if h == target_hash:
            with lock:
                stats["tried"] += local_count
                result["hash"]  = target_hash
                result["plain"] = pwd
                result["algo"]  = algo
            found.set()
            q.task_done()
            break

        q.task_done()
        if found.is_set():
            break

    if local_count:
        with lock:
            stats["tried"] += local_count

# ─── MODO: Rainbow Table ───────────────────────────────────────────────────────
def generate_rainbow_table(algo, size, output_path, charset_name):
    charset = CHARSETS.get(charset_name, CHARSETS["alphanum"])
    print(f"\n  {B}[*]{RST} Gerando Rainbow Table")
    print(f"  {B}[*]{RST} Algoritmo: {algo.upper()}")
    print(f"  {B}[*]{RST} Entradas  : {size:,}")
    print(f"  {B}[*]{RST} Saída     : {output_path}\n")

    # Palavras comuns + geradas
    common = [
        "password","123456","admin","letmein","welcome","monkey","dragon",
        "master","shadow","iloveyou","sunshine","princess","qwerty","abc123",
        "password1","superman","batman","donald","michael","jessica","thomas",
    ]

    table = {}
    t0    = time.time()
    count = 0

    # Adicionar palavras comuns primeiro
    for w in common:
        if count >= size: break
        h = do_hash(w, algo)
        table[h] = w
        count += 1

    # Gerar combinações 1-5 chars
    for length in range(1, 6):
        if count >= size: break
        for combo in itertools.product(charset, repeat=length):
            if count >= size: break
            w = "".join(combo)
            h = do_hash(w, algo)
            if h not in table:
                table[h] = w
                count += 1
                if count % 10000 == 0:
                    elapsed = time.time()-t0
                    speed   = count/elapsed if elapsed > 0 else 0
                    pct     = int((count/size)*40)
                    bar     = f"{G}{'█'*pct}{DIM}{'░'*(40-pct)}{RST}"
                    print(f"\r  [{bar}] {count:,}/{size:,} @ {speed:,.0f}/s", end="", flush=True)

    elapsed = time.time()-t0
    print(f"\r  [{G}{'█'*40}{RST}] {count:,}/{size:,} {G}✓{RST}    ")

    # Salvar
    with open(output_path, "w") as f:
        json.dump(table, f)

    size_kb = os.path.getsize(output_path)/1024
    print(f"\n  {G}[✓]{RST} Rainbow table gerada: {count:,} entradas")
    print(f"  {G}[✓]{RST} Tamanho: {size_kb:.1f} KB")
    print(f"  {G}[✓]{RST} Salva em: {output_path}")
    print(f"  {DIM}Tempo: {elapsed:.2f}s | Velocidade: {count/elapsed:,.0f}/s{RST}")

# ─── MODO: Rainbow Lookup ──────────────────────────────────────────────────────
def rainbow_lookup(target_hash, rainbow_path):
    if not os.path.exists(rainbow_path):
        print(f"{R}[ERRO] Rainbow table não encontrada: {rainbow_path}{RST}")
        return None
    print(f"  {B}[*]{RST} Carregando rainbow table...")
    with open(rainbow_path) as f:
        table = json.load(f)
    print(f"  {B}[*]{RST} {len(table):,} entradas carregadas")
    return table.get(target_hash.lower())

# ─── BENCHMARK ─────────────────────────────────────────────────────────────────
def benchmark():
    print(f"\n  {Y}[BENCHMARK]{RST} Testando velocidade de hash...\n")
    test_str = "benchmark_test_password"
    iterations = 500_000

    for name, (func, length, label) in ALGOS.items():
        t0  = time.time()
        for i in range(iterations):
            h = func()
            h.update(f"{test_str}{i}".encode())
            _ = h.hexdigest()
        elapsed = time.time()-t0
        speed   = iterations/elapsed
        bar_len = int(speed/2_000_000*30)
        bar     = f"{G}{'█'*min(bar_len,30)}{RST}"
        print(f"  {C}{label:<12}{RST} {bar:<32} {W}{speed:>12,.0f}{RST} H/s")

# ─── SPEED MONITOR ────────────────────────────────────────────────────────────
def speed_monitor_thread():
    last = 0
    while not found.is_set():
        time.sleep(2)
        current = stats["tried"]
        elapsed = time.time()-stats["start"]
        speed   = (current-last)/2
        print(f"\r  {DIM}[{int(elapsed)}s] tried: {current:,} | speed: {speed:,.0f}/s     {RST}",
              end="", flush=True)
        last = current

# ─── Main ──────────────────────────────────────────────────────────────────────
def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Advanced Hash Cracker — Python puro")
    parser.add_argument("--identify",  help="Identificar tipo de hash")
    parser.add_argument("--crack",     help="Hash para crackear")
    parser.add_argument("--algo",      default="auto", help="Algoritmo: md5,sha1,sha256...")
    parser.add_argument("--wordlist",  default=None, help="Wordlist")
    parser.add_argument("--brute",     action="store_true", help="Modo brute force")
    parser.add_argument("--charset",   default="alphanum", help="Charset para brute")
    parser.add_argument("--min",       type=int, default=1, help="Comprimento mínimo")
    parser.add_argument("--max",       type=int, default=5, help="Comprimento máximo")
    parser.add_argument("--salt",      default="", help="Salt da senha")
    parser.add_argument("--salt-pos",  default="prefix", choices=["prefix","suffix"])
    parser.add_argument("--rules",     action="store_true", help="Aplicar regras de mutação")
    parser.add_argument("--rainbow",   action="store_true", help="Gerar rainbow table")
    parser.add_argument("--rainbow-file", default="rainbow.json", help="Arquivo rainbow table")
    parser.add_argument("--rainbow-lookup", help="Fazer lookup na rainbow table")
    parser.add_argument("--size",      type=int, default=100000, help="Tamanho da rainbow table")
    parser.add_argument("--threads",   type=int, default=8, help="Threads")
    parser.add_argument("--benchmark", action="store_true", help="Benchmark de algoritmos")
    args = parser.parse_args()

    # ── Benchmark ──
    if args.benchmark:
        benchmark()
        return

    # ── Identificar hash ──
    if args.identify:
        h = args.identify.strip()
        print(f"  {B}[*]{RST} Hash     : {W}{h}{RST}")
        print(f"  {B}[*]{RST} Tamanho  : {len(h)} chars\n")
        candidates = identify_hash(h)
        print(f"  {Y}[CANDIDATOS]{RST}")
        for algo, detail in candidates:
            print(f"  {G}→{RST} {W}{algo:<20}{RST} {DIM}{detail}{RST}")
        return

    # ── Rainbow table ──
    if args.rainbow:
        if args.algo == "auto": args.algo = "md5"
        generate_rainbow_table(args.algo, args.size, args.rainbow_file, args.charset)
        return

    # ── Rainbow lookup ──
    if args.rainbow_lookup:
        plain = rainbow_lookup(args.rainbow_lookup, args.rainbow_file)
        if plain:
            print(f"  {G}[ENCONTRADO]{RST} {args.rainbow_lookup} → {BOLD}{W}{plain}{RST}")
        else:
            print(f"  {R}[NÃO ENCONTRADO]{RST} Hash não está na rainbow table.")
        return

    # ── Crackear ──
    if not args.crack:
        print(f"{R}[ERRO] Forneça --crack <hash>, --identify <hash>, --rainbow ou --benchmark{RST}")
        sys.exit(1)

    target = args.crack.strip().lower()

    # Auto detect algo
    algo = args.algo
    if algo == "auto":
        candidates = identify_hash(target)
        # Pega o primeiro que é suportado
        for cand, _ in candidates:
            if cand in ALGOS:
                algo = cand
                print(f"  {Y}[*]{RST} Auto-detectado: {algo.upper()}")
                break
        if algo == "auto":
            algo = "md5"
            print(f"  {Y}[*]{RST} Usando padrão: MD5")

    print(f"  {B}[*]{RST} Hash     : {W}{target[:32]}...{RST}" if len(target) > 32 else f"  {B}[*]{RST} Hash: {W}{target}{RST}")
    print(f"  {B}[*]{RST} Algoritmo: {algo.upper()}")
    print(f"  {B}[*]{RST} Salt     : {repr(args.salt) if args.salt else 'Nenhum'}")
    print(f"  {B}[*]{RST} Threads  : {args.threads}")

    # Monitor de velocidade
    mon = threading.Thread(target=speed_monitor_thread, daemon=True)
    mon.start()

    t0 = time.time()
    q  = Queue(maxsize=100000)

    if args.brute:
        charset = CHARSETS.get(args.charset, CHARSETS["alphanum"])
        total   = sum(len(charset)**l for l in range(args.min, args.max+1))
        print(f"  {B}[*]{RST} Modo     : BRUTE FORCE")
        print(f"  {B}[*]{RST} Charset  : {args.charset} ({len(charset)} chars)")
        print(f"  {B}[*]{RST} Total    : {total:,}\n")

        threads = [threading.Thread(
            target=brute_worker,
            args=(target, algo, q, args.salt, args.salt_pos),
            daemon=True
        ) for _ in range(args.threads)]
        for t in threads: t.start()

        for length in range(args.min, args.max+1):
            if found.is_set(): break
            for combo in itertools.product(charset, repeat=length):
                if found.is_set(): break
                q.put("".join(combo))
        # Sinaliza fim da fila e aguarda workers
        found.set() if not found.is_set() else None  # garante que workers saiam
        for t in threads: t.join(timeout=5)

    else:
        wl_path = args.wordlist
        if not wl_path:
            print(f"{R}[ERRO] Modo dict requer --wordlist. Use --brute para brute force.{RST}")
            sys.exit(1)
        if not os.path.exists(wl_path):
            print(f"{R}[ERRO] Wordlist não encontrada: {wl_path}{RST}")
            sys.exit(1)

        print(f"  {B}[*]{RST} Modo     : DICIONÁRIO")
        print(f"  {B}[*]{RST} Wordlist : {wl_path}\n")

        threads = [threading.Thread(
            target=dict_worker,
            args=(target, algo, q, args.salt, args.salt_pos, args.rules),
            daemon=True
        ) for _ in range(args.threads)]
        for t in threads: t.start()

        with open(wl_path,"r",encoding="utf-8",errors="ignore") as f:
            for line in f:
                if found.is_set(): break
                w = line.strip()
                if w: q.put(w)
        q.join()

    elapsed = time.time()-t0
    print(f"\n\n{C}{'─'*55}{RST}")
    print(f"{BOLD}  RESULTADO{RST}")
    print(f"{C}{'─'*55}{RST}")
    print(f"  Tentativas : {stats['tried']:,}")
    print(f"  Velocidade : {stats['tried']/elapsed:,.0f} H/s")
    print(f"  Tempo      : {elapsed:.2f}s")

    if found.is_set():
        print(f"\n  {G}{BOLD}[✓] HASH CRACKEADO!{RST}")
        print(f"  Hash  : {DIM}{result['hash']}{RST}")
        print(f"  Senha : {G}{BOLD}{result['plain']}{RST}")
    else:
        print(f"\n  {R}[✗] Hash não crackeado.{RST}")
        print(f"  {DIM}Tente uma wordlist maior ou mude o modo de ataque.{RST}")

if __name__ == "__main__":
    main()
