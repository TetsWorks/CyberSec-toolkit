#!/usr/bin/env python3
"""
╔══════════════════════════════════════════╗
║       ADVANCED PASSWORD CRACKER          ║
║  Brute Force | Dict | Híbrido | Mask     ║
╚══════════════════════════════════════════╝
Uso:
  python3 password_cracker.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --type md5 --mode dict --wordlist rockyou.txt
  python3 password_cracker.py --hash <sha256> --type sha256 --mode brute --charset alpha --min 3 --max 6
  python3 password_cracker.py --hash <hash> --type sha1 --mode mask --mask "?u?l?l?l?d?d"
  python3 password_cracker.py --file hashes.txt --type md5 --mode dict --wordlist words.txt
"""

import hashlib
import itertools
import threading
import argparse
import sys
import time
import os
import string
from queue import Queue
from datetime import datetime

# ─── Cores ────────────────────────────────────────────────────────────────────
R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
M="\033[95m"; C="\033[96m"; W="\033[97m"; DIM="\033[2m"; RST="\033[0m"; BOLD="\033[1m"

# ─── Charsets ─────────────────────────────────────────────────────────────────
CHARSETS = {
    "alpha"    : string.ascii_lowercase,
    "ALPHA"    : string.ascii_uppercase,
    "alphanum" : string.ascii_lowercase + string.digits,
    "ALPHANUM" : string.ascii_letters + string.digits,
    "numeric"  : string.digits,
    "special"  : string.punctuation,
    "full"     : string.ascii_letters + string.digits + string.punctuation,
}

# ─── Mask charset (estilo hashcat) ────────────────────────────────────────────
MASK_CHARS = {
    "?l": string.ascii_lowercase,
    "?u": string.ascii_uppercase,
    "?d": string.digits,
    "?s": string.punctuation,
    "?a": string.ascii_letters + string.digits + string.punctuation,
}

# ─── Suporte a algoritmos ─────────────────────────────────────────────────────
HASH_FUNCS = {
    "md5"    : hashlib.md5,
    "sha1"   : hashlib.sha1,
    "sha224" : hashlib.sha224,
    "sha256" : hashlib.sha256,
    "sha384" : hashlib.sha384,
    "sha512" : hashlib.sha512,
    "sha3_256": hashlib.sha3_256,
    "sha3_512": hashlib.sha3_512,
    "blake2b": hashlib.blake2b,
    "blake2s": hashlib.blake2s,
    "ntlm"   : None,   # Tratado especialmente
}

def _ntlm_hash(text):
    """NTLM = MD4(UTF-16LE(password))."""
    data = text.encode("utf-16-le")
    try:
        h = hashlib.new("md4")
        h.update(data)
        return h.hexdigest()
    except ValueError:
        # MD4 indisponível — avisa
        print(f"  {Y}[!]{RST} md4 não disponível via OpenSSL — NTLM pode falhar")
        return ""


# ─── Estado global ────────────────────────────────────────────────────────────
found   = threading.Event()
results = {}
stats   = {"tried": 0, "start": time.time()}
lock    = threading.Lock()

def print_banner():
    print(f"""
{R}╔{'═'*54}╗
║  {W}{BOLD} ██████╗ ██████╗  █████╗  ██████╗██╗  ██╗          {R}║
║  {W}{BOLD} ██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝          {R}║
║  {W}{BOLD} ██║     ██████╔╝███████║██║     █████╔╝            {R}║
║  {W}{BOLD} ██║     ██╔══██╗██╔══██║██║     ██╔═██╗            {R}║
║  {W}{BOLD} ╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗           {R}║
║  {W}{BOLD}  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝          {R}║
║{Y}         P A S S W O R D   C R A C K E R             {R}║
╚{'═'*54}╝{RST}
{DIM}  [*] Apenas para fins educacionais e hashes próprios.{RST}
""")

# ─── Hash de uma string ────────────────────────────────────────────────────────
def hash_string(s, algo):
    if algo == "ntlm":
        return _ntlm_hash(s)
    try:
        h = HASH_FUNCS[algo]()
        h.update(s.encode("utf-8", errors="ignore"))
        return h.hexdigest()
    except:
        return ""

def detect_hash_type(h):
    h = h.strip().lower()
    # Prefixos especiais
    if h.startswith("$2"):            return "bcrypt"
    if h.startswith("$argon2"):       return "argon2"
    if h.startswith("$6$"):           return "sha512-crypt"
    if h.startswith("$5$"):           return "sha256-crypt"
    if h.startswith("$1$"):           return "md5-crypt"
    if h.startswith("$p$") or h.startswith("$h$"): return "phpass"
    # Por tamanho
    sizes = {32:"md5",40:"sha1",56:"sha224",64:"sha256",96:"sha384",128:"sha512"}
    detected = sizes.get(len(h), "desconhecido")
    # MD5 e NTLM têm o mesmo comprimento (32) — NTLM geralmente vem de dumps Windows
    # Não há como diferenciar automaticamente, então retorna md5 mas informa
    return detected


# ─── Barra de progresso de velocidade ─────────────────────────────────────────
def speed_monitor():
    last = 0
    while not found.is_set():
        time.sleep(2)
        current = stats["tried"]
        speed   = (current - last) / 2
        elapsed = time.time() - stats["start"]
        print(f"\r  {DIM}[{int(elapsed)}s] tentativas: {current:,} | velocidade: {speed:,.0f}/s     {RST}",
              end="", flush=True)
        last = current

# ─── Testa uma senha contra todos os hashes alvos ─────────────────────────────
def test_password(pwd, targets, algo):
    h = hash_string(pwd, algo)
    # Incrementa stats sem lock (leve race condition aceitável no contador)
    stats["tried"] += 1
    if h in targets and h not in results:
        with lock:
            if h not in results:  # double-check sob lock
                results[h] = pwd
        print(f"\n  {G}{BOLD}[CRACK] {W}{h[:20]}...{RST} → {G}{BOLD}{pwd}{RST}")
        if len(results) >= len(targets):
            found.set()

# ─── MODO: Dicionário ──────────────────────────────────────────────────────────
def mode_dict(wordlist_path, targets, algo, threads_n, rules):
    if not os.path.exists(wordlist_path):
        print(f"{R}[ERRO] Wordlist não encontrada: {wordlist_path}{RST}")
        sys.exit(1)

    print(f"  {B}[*]{RST} Modo       : DICIONÁRIO")
    print(f"  {B}[*]{RST} Wordlist   : {wordlist_path}")
    print(f"  {B}[*]{RST} Regras     : {'Ativadas' if rules else 'Desativadas'}")

    q = Queue(maxsize=10000)

    def worker():
        while True:
            try:
                pwd = q.get(timeout=0.5)
            except:
                break
            test_password(pwd, targets, algo)
            if not found.is_set() and rules:
                for variation in apply_rules(pwd):
                    if found.is_set(): break
                    test_password(variation, targets, algo)
            q.task_done()
            if found.is_set():
                break

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(threads_n)]
    for t in threads: t.start()

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if found.is_set():
                break
            pwd = line.strip()
            if pwd:
                q.put(pwd)

    for t in threads: t.join(timeout=10)

# ─── Regras de mutação de senha ───────────────────────────────────────────────
def apply_rules(word):
    variations = set()
    variations.add(word.capitalize())
    variations.add(word.upper())
    variations.add(word.lower())
    variations.add(word + "123")
    variations.add(word + "!")
    variations.add(word + "2024")
    variations.add(word + "1")
    # L33tspeak
    leet = word.replace("a","@").replace("e","3").replace("i","1").replace("o","0").replace("s","$")
    variations.add(leet)
    return variations - {word}

# ─── MODO: Brute Force ────────────────────────────────────────────────────────
def mode_brute(charset_name, min_len, max_len, targets, algo, threads_n):
    charset = CHARSETS.get(charset_name, CHARSETS["alpha"])

    print(f"  {B}[*]{RST} Modo       : BRUTE FORCE")
    print(f"  {B}[*]{RST} Charset    : {charset_name} ({len(charset)} chars)")
    print(f"  {B}[*]{RST} Comprimento: {min_len}–{max_len}")

    total = sum(len(charset)**l for l in range(min_len, max_len+1))
    print(f"  {B}[*]{RST} Total comb.: {total:,}")

    q = Queue(maxsize=50000)

    def worker():
        while True:
            try:
                pwd = q.get(timeout=0.5)
            except:
                break
            test_password(pwd, targets, algo)
            q.task_done()
            if found.is_set():
                break

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(threads_n)]
    for t in threads: t.start()

    for length in range(min_len, max_len + 1):
        if found.is_set(): break
        print(f"\n  {Y}[>]{RST} Comprimento {length}...")
        for combo in itertools.product(charset, repeat=length):
            if found.is_set(): break
            q.put("".join(combo))

    for t in threads: t.join(timeout=15)

# ─── MODO: Mask Attack (estilo hashcat) ───────────────────────────────────────
def mode_mask(mask, targets, algo, threads_n):
    print(f"  {B}[*]{RST} Modo  : MASK ATTACK")
    print(f"  {B}[*]{RST} Máscara: {mask}")

    # Parse a máscara em lista de charsets
    segments = []
    i = 0
    while i < len(mask):
        token = mask[i:i+2]
        if token in MASK_CHARS:
            segments.append(MASK_CHARS[token])
            i += 2
        else:
            segments.append([mask[i]])
            i += 1

    total = 1
    for seg in segments: total *= len(seg)
    print(f"  {B}[*]{RST} Combinações: {total:,}")

    q = Queue(maxsize=50000)

    def worker():
        while True:
            try:
                pwd = q.get(timeout=0.5)
            except:
                break
            test_password(pwd, targets, algo)
            q.task_done()
            if found.is_set():
                break

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(threads_n)]
    for t in threads: t.start()

    for combo in itertools.product(*segments):
        if found.is_set(): break
        q.put("".join(combo))

    for t in threads: t.join(timeout=15)

# ─── MODO: Híbrido (dict + brute sufixo) ─────────────────────────────────────
def mode_hybrid(wordlist_path, suffix_len, suffix_charset, targets, algo, threads_n,
                prefix_len=0, prefix_charset="numeric"):
    """
    Modo híbrido melhorado:
    - Sufixo brute (palavra + brute)
    - Prefixo brute (brute + palavra)
    - Combina os dois se especificado
    """
    charset_suf = CHARSETS.get(suffix_charset, string.digits)
    charset_pre = CHARSETS.get(prefix_charset, string.digits)

    print(f"  {B}[*]{RST} Modo  : HÍBRIDO AVANÇADO")
    print(f"  {B}[*]{RST} Sufixo: {suffix_len} chars de '{suffix_charset}'")
    if prefix_len > 0:
        print(f"  {B}[*]{RST} Prefixo: {prefix_len} chars de '{prefix_charset}'")

    # Hybrid roda diretamente no producer (sem Queue) para evitar race condition
    # entre producer gerando candidatos e workers saindo por timeout
    with open(wordlist_path,"r",encoding="utf-8",errors="ignore") as f:
        for line in f:
            if found.is_set(): break
            word = line.strip()
            if not word: continue
            bases = [word, word.capitalize(), word.lower(), word.upper(),
                     word + "!", word + "1", word + "123"]
            for base in bases:
                if found.is_set(): break
                # Sufixo
                for combo in itertools.product(charset_suf, repeat=suffix_len):
                    if found.is_set(): break
                    test_password(base + "".join(combo), targets, algo)
                # Prefixo
                if prefix_len > 0:
                    for combo in itertools.product(charset_pre, repeat=prefix_len):
                        if found.is_set(): break
                        test_password("".join(combo) + base, targets, algo)


# ─── Main ──────────────────────────────────────────────────────────────────────
def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Advanced Password Cracker — Python puro")
    parser.add_argument("--hash",     help="Hash alvo único")
    parser.add_argument("--file",     help="Arquivo com múltiplos hashes (um por linha)")
    parser.add_argument("--type",     default="auto",
                        help="Tipo: md5,sha1,sha256,ntlm,bcrypt... (padrão: auto)")
    parser.add_argument("--mode",     default="dict", help="Modo: dict,brute,mask,hybrid")
    parser.add_argument("--wordlist", default="wordlist.txt", help="Caminho da wordlist")
    parser.add_argument("--charset",  default="alpha", help="Charset p/ brute: alpha,alphanum,full...")
    parser.add_argument("--min",      type=int, default=1, help="Comprimento mínimo (brute)")
    parser.add_argument("--max",      type=int, default=5, help="Comprimento máximo (brute)")
    parser.add_argument("--mask",     default="?l?l?l?l?d?d",
                        help="Máscara (?l=lower,?u=upper,?d=digit,?s=special)")
    parser.add_argument("--threads",  type=int, default=8, help="Threads (padrão: 8)")
    parser.add_argument("--rules",    action="store_true", help="Aplicar regras de mutação (modo dict)")
    parser.add_argument("--suffix",   type=int, default=2, help="Tamanho do sufixo (modo hybrid)")
    parser.add_argument("--prefix",   type=int, default=0,
                        help="Tamanho do prefixo (modo hybrid) — 0=desativado")
    parser.add_argument("--prefix-charset", default="numeric",
                        help="Charset do prefixo (modo hybrid)")
    parser.add_argument("--output",   default=None, help="Salvar resultado em JSON")

    args = parser.parse_args()

    # Coletar hashes alvos
    targets = set()
    if args.hash:
        targets.add(args.hash.lower().strip())
    if args.file:
        if not os.path.exists(args.file):
            print(f"{R}[ERRO] Arquivo de hashes não encontrado: {args.file}{RST}")
            sys.exit(1)
        with open(args.file) as f:
            for l in f:
                h = l.strip().lower()
                if h: targets.add(h)

    if not targets:
        print(f"{R}[ERRO] Forneça --hash ou --file{RST}")
        sys.exit(1)

    # Auto detectar tipo
    algo = args.type
    if algo == "auto":
        sample = next(iter(targets))
        algo = detect_hash_type(sample)
        print(f"  {Y}[*]{RST} Hash auto-detectado: {algo.upper()} ({len(sample)} chars)")

    if algo not in HASH_FUNCS:
        print(f"{R}[ERRO] Algoritmo '{algo}' não suportado.{RST}")
        print(f"  Disponíveis: {', '.join(HASH_FUNCS.keys())}")
        sys.exit(1)

    print(f"\n  {B}[*]{RST} Alvos    : {len(targets)} hash(es)")
    print(f"  {B}[*]{RST} Algoritmo: {algo.upper()}")
    print(f"  {B}[*]{RST} Threads  : {args.threads}")

    # Inicia monitor de velocidade
    mon = threading.Thread(target=speed_monitor, daemon=True)
    mon.start()

    t0 = time.time()

    if args.mode == "dict":
        mode_dict(args.wordlist, targets, algo, args.threads, args.rules)
    elif args.mode == "brute":
        mode_brute(args.charset, args.min, args.max, targets, algo, args.threads)
    elif args.mode == "mask":
        mode_mask(args.mask, targets, algo, args.threads)
    elif args.mode == "hybrid":
        mode_hybrid(args.wordlist, args.suffix, args.charset, targets, algo, args.threads,
                    prefix_len=args.prefix, prefix_charset=args.prefix_charset)
    else:
        print(f"{R}[ERRO] Modo desconhecido: {args.mode}{RST}")
        sys.exit(1)

    elapsed = time.time() - t0
    print(f"\n\n{C}{'─'*55}{RST}")
    print(f"{BOLD}  RESULTADO FINAL{RST}")
    print(f"{C}{'─'*55}{RST}")
    print(f"  Tentativas : {stats['tried']:,}")
    print(f"  Velocidade : {stats['tried']/elapsed:,.0f}/s")
    print(f"  Tempo      : {elapsed:.2f}s")
    print(f"  Crackeados : {G}{len(results)}{RST}/{len(targets)}")

    if results:
        print(f"\n  {BOLD}SENHAS ENCONTRADAS:{RST}")
        for h, pwd in results.items():
            print(f"  {G}{h}{RST} → {BOLD}{W}{pwd}{RST}")
    else:
        print(f"\n  {R}Nenhuma senha encontrada com as configurações atuais.{RST}")

    if args.output:
        import json as _json
        out = {
            "algo": algo, "mode": args.mode,
            "tried": stats["tried"], "elapsed": elapsed,
            "cracked": len(results), "total": len(targets),
            "results": {h: p for h,p in results.items()}
        }
        with open(args.output, "w") as f:
            _json.dump(out, f, indent=2)
        print(f"\n  {G}[✓]{RST} Resultado salvo em: {args.output}")


if __name__ == "__main__":
    main()
