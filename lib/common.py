#!/usr/bin/env python3
"""
lib/common.py — Biblioteca compartilhada do CyberSec Toolkit v2
Fornece: cores ANSI, reporter multi-formato (JSON/HTML/TXT), utilitários comuns
"""

import json
import os
import sys
import socket
import time
from datetime import datetime

# ─── Cores ANSI ───────────────────────────────────────────────────────────────
R    = "\033[91m"
G    = "\033[92m"
Y    = "\033[93m"
B    = "\033[94m"
M    = "\033[95m"
C    = "\033[96m"
W    = "\033[97m"
DIM  = "\033[2m"
RST  = "\033[0m"
BOLD = "\033[1m"

def strip_ansi(text):
    import re
    return re.sub(r'\033\[[0-9;]*m', '', text)

# ─── Reporter Multi-Formato ───────────────────────────────────────────────────
class Reporter:
    """Coleta findings e exporta em TXT, JSON e/ou HTML."""

    def __init__(self, tool_name: str, target: str):
        self.tool_name  = tool_name
        self.target     = target
        self.started_at = datetime.now()
        self.findings   = []       # lista de dicts
        self.meta       = {}       # metadados extras

    def add(self, category: str, severity: str, title: str, detail: str = "", raw: dict = None):
        """
        severity: INFO | LOW | MEDIUM | HIGH | CRITICAL
        """
        self.findings.append({
            "timestamp": datetime.now().isoformat(),
            "category" : category,
            "severity" : severity,
            "title"    : title,
            "detail"   : detail,
            "raw"      : raw or {},
        })

    def set_meta(self, key, value):
        self.meta[key] = value

    # ── TXT ──
    def save_txt(self, path: str):
        sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
        sorted_f  = sorted(self.findings, key=lambda x: sev_order.get(x["severity"],99))
        lines = []
        lines.append(f"{'='*65}")
        lines.append(f"  {self.tool_name.upper()} — {self.target}")
        lines.append(f"  Gerado em: {self.started_at.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"{'='*65}\n")
        if self.meta:
            for k,v in self.meta.items():
                lines.append(f"  {k}: {v}")
            lines.append("")
        lines.append(f"FINDINGS ({len(self.findings)}):")
        lines.append(f"{'─'*65}")
        for f in sorted_f:
            lines.append(f"\n[{f['severity']}] {f['category']} — {f['title']}")
            if f['detail']:
                lines.append(f"  {f['detail']}")
        lines.append(f"\n{'='*65}")
        with open(path,"w",encoding="utf-8") as fh:
            fh.write("\n".join(lines))

    # ── JSON ──
    def save_json(self, path: str):
        data = {
            "tool"      : self.tool_name,
            "target"    : self.target,
            "started_at": self.started_at.isoformat(),
            "ended_at"  : datetime.now().isoformat(),
            "meta"      : self.meta,
            "summary"   : {
                "total"   : len(self.findings),
                "critical": sum(1 for f in self.findings if f["severity"]=="CRITICAL"),
                "high"    : sum(1 for f in self.findings if f["severity"]=="HIGH"),
                "medium"  : sum(1 for f in self.findings if f["severity"]=="MEDIUM"),
                "low"     : sum(1 for f in self.findings if f["severity"]=="LOW"),
                "info"    : sum(1 for f in self.findings if f["severity"]=="INFO"),
            },
            "findings"  : self.findings,
        }
        with open(path,"w",encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)

    # ── HTML ──
    def save_html(self, path: str):
        sev_color = {
            "CRITICAL": "#e74c3c",
            "HIGH"    : "#e67e22",
            "MEDIUM"  : "#f1c40f",
            "LOW"     : "#3498db",
            "INFO"    : "#95a5a6",
        }
        sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
        sorted_f  = sorted(self.findings, key=lambda x: sev_order.get(x["severity"],99))

        summary = {s:sum(1 for f in self.findings if f["severity"]==s)
                   for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}

        rows = ""
        for f in sorted_f:
            color = sev_color.get(f["severity"],"#ccc")
            detail_html = f["detail"].replace("<","&lt;").replace(">","&gt;").replace("\n","<br>")
            rows += f"""
            <tr>
              <td><span class="badge" style="background:{color}">{f['severity']}</span></td>
              <td>{f['category']}</td>
              <td>{f['title']}</td>
              <td class="detail">{detail_html}</td>
              <td class="ts">{f['timestamp'][11:19]}</td>
            </tr>"""

        meta_rows = "".join(f"<tr><td><b>{k}</b></td><td>{v}</td></tr>" for k,v in self.meta.items())

        summary_cards = ""
        for sev, cnt in summary.items():
            color = sev_color[sev]
            summary_cards += f'<div class="card" style="border-top:4px solid {color}"><div class="card-num" style="color:{color}">{cnt}</div><div class="card-label">{sev}</div></div>'

        html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{self.tool_name} — {self.target}</title>
<style>
  :root{{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#58a6ff}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;padding:2rem}}
  h1{{font-size:1.6rem;color:var(--accent);margin-bottom:.3rem}}
  .subtitle{{color:var(--muted);font-size:.9rem;margin-bottom:2rem}}
  .summary{{display:flex;gap:1rem;margin-bottom:2rem;flex-wrap:wrap}}
  .card{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem 1.5rem;min-width:110px;text-align:center}}
  .card-num{{font-size:2rem;font-weight:700}}
  .card-label{{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-top:.2rem}}
  table{{width:100%;border-collapse:collapse;background:var(--card);border-radius:8px;overflow:hidden;border:1px solid var(--border)}}
  th{{background:#21262d;padding:.75rem 1rem;text-align:left;font-size:.8rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}}
  td{{padding:.7rem 1rem;border-top:1px solid var(--border);font-size:.875rem;vertical-align:top}}
  tr:hover td{{background:#1c2128}}
  .badge{{display:inline-block;padding:.2em .6em;border-radius:4px;font-size:.75rem;font-weight:700;color:#fff}}
  .detail{{color:var(--muted);font-family:monospace;font-size:.8rem;max-width:400px;word-break:break-all}}
  .ts{{color:var(--muted);font-family:monospace;font-size:.8rem;white-space:nowrap}}
  .meta-table{{margin-bottom:2rem;max-width:600px}}
  .meta-table td{{font-size:.85rem;padding:.4rem .8rem}}
  .section-title{{color:var(--muted);font-size:.8rem;text-transform:uppercase;letter-spacing:.1em;margin-bottom:.75rem;margin-top:2rem}}
  footer{{margin-top:3rem;color:var(--muted);font-size:.8rem;text-align:center}}
</style>
</head>
<body>
<h1>🔒 {self.tool_name}</h1>
<div class="subtitle">Alvo: <b>{self.target}</b> &nbsp;|&nbsp; {self.started_at.strftime('%Y-%m-%d %H:%M:%S')}</div>

<div class="summary">{summary_cards}</div>

{f'<p class="section-title">Informações</p><table class="meta-table"><tbody>{meta_rows}</tbody></table>' if meta_rows else ''}

<p class="section-title">Findings — {len(self.findings)} total</p>
<table>
  <thead><tr><th>Severidade</th><th>Categoria</th><th>Título</th><th>Detalhe</th><th>Hora</th></tr></thead>
  <tbody>{rows if rows else '<tr><td colspan="5" style="text-align:center;color:var(--muted)">Nenhum finding.</td></tr>'}</tbody>
</table>

<footer>CyberSec Toolkit v2 — gerado em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</footer>
</body>
</html>"""
        with open(path,"w",encoding="utf-8") as fh:
            fh.write(html)

    def save_all(self, base_path: str):
        """Salva TXT, JSON e HTML a partir de um caminho base (sem extensão)."""
        self.save_txt(base_path + ".txt")
        self.save_json(base_path + ".json")
        self.save_html(base_path + ".html")
        print(f"\n  {G}[✓]{RST} Relatórios salvos:")
        print(f"      {DIM}{base_path}.txt{RST}")
        print(f"      {DIM}{base_path}.json{RST}")
        print(f"      {DIM}{base_path}.html{RST}")

# ─── Utilitários ──────────────────────────────────────────────────────────────
def resolve(host):
    try:
        return socket.gethostbyname(host)
    except:
        return None

def print_header(title: str, subtitle: str, color: str = C):
    w = 58
    print(f"\n{color}╔{'═'*w}╗")
    print(f"║{W}{BOLD}  {title:<{w-2}}{color}║")
    print(f"║{DIM}  {subtitle:<{w-2}}{color}║")
    print(f"╚{'═'*w}╝{RST}")
    print(f"{DIM}  [!] Apenas em alvos com autorização explícita.{RST}\n")

def severity_color(sev: str) -> str:
    return {
        "CRITICAL": R+BOLD,
        "HIGH"    : R,
        "MEDIUM"  : Y,
        "LOW"     : B,
        "INFO"    : DIM,
    }.get(sev, W)

def print_finding(sev: str, category: str, title: str, detail: str = ""):
    sc = severity_color(sev)
    print(f"  {sc}[{sev:<8}]{RST} {W}{category}{RST} — {title}")
    if detail:
        for line in detail.strip().split("\n"):
            print(f"             {DIM}{line}{RST}")
