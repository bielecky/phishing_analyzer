"""
report.py
Formata os resultados da análise para três públicos diferentes:
  - console (leitura rápida durante a triagem, com cores se 'rich' estiver disponível)
  - JSON (para alimentar SIEM/SOAR, anexar a um ticket, etc.)
  - HTML (para anexar em e-mail de escalonamento ou guardar como evidência)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False


def _verdict_color(verdict: str) -> str:
    if verdict.startswith("ALTO"):
        return "red"
    if verdict.startswith("SUSPEITO"):
        return "yellow"
    if verdict.startswith("BAIXO"):
        return "cyan"
    return "green"


def print_console_report(parsed_email, header_findings, url_findings, score_result,
                          vt_domain_results=None, whois_results=None):
    vt_domain_results = vt_domain_results or {}
    whois_results = whois_results or {}

    if not _HAS_RICH:
        _print_plain_report(parsed_email, header_findings, url_findings, score_result,
                             vt_domain_results, whois_results)
        return

    console = Console()
    color = _verdict_color(score_result.verdict)

    console.print(Panel.fit(
        f"[bold]{score_result.verdict}[/bold]\nScore: {score_result.total_score}/100",
        border_style=color,
        title="Veredito",
    ))

    meta = Table(title="Metadados do e-mail", show_header=False)
    meta.add_row("Assunto", parsed_email.headers.get("subject", ""))
    meta.add_row("De", parsed_email.headers["from"]["raw"])
    meta.add_row("Reply-To", parsed_email.headers["reply_to"]["raw"] or "(ausente)")
    meta.add_row("Return-Path", parsed_email.headers["return_path"]["raw"] or "(ausente)")
    meta.add_row("Data", parsed_email.headers.get("date", ""))
    console.print(meta)

    if score_result.hits:
        table = Table(title="Indicadores encontrados")
        table.add_column("Regra")
        table.add_column("Peso", justify="right")
        table.add_column("Descrição")
        for hit in sorted(score_result.hits, key=lambda h: -h.weight):
            table.add_row(hit.rule_id, f"+{hit.weight}", hit.description)
        console.print(table)
    else:
        console.print("[green]Nenhum indicador de risco disparado.[/green]")

    if url_findings:
        url_table = Table(title="URLs encontradas")
        url_table.add_column("Domínio")
        url_table.add_column("Sinalizações")
        for uf in url_findings:
            flags = []
            if uf.typosquat_of:
                flags.append(f"typosquat de {uf.typosquat_of}")
            if uf.anchor_mismatch:
                flags.append("texto≠destino")
            if uf.is_shortener:
                flags.append("encurtador")
            if uf.is_punycode:
                flags.append("punycode")
            if uf.is_ip_literal:
                flags.append("IP literal")
            if uf.suspicious_tld:
                flags.append("TLD suspeito")
            url_table.add_row(uf.domain, ", ".join(flags) or "-")
        console.print(url_table)

    if parsed_email.attachments:
        att_table = Table(title="Anexos")
        att_table.add_column("Nome")
        att_table.add_column("Tipo")
        att_table.add_column("SHA256")
        for att in parsed_email.attachments:
            att_table.add_row(att.filename, att.content_type, att.sha256[:16] + "…" if att.sha256 else "-")
        console.print(att_table)


def _print_plain_report(parsed_email, header_findings, url_findings, score_result,
                         vt_domain_results, whois_results):
    print("=" * 70)
    print(f"VEREDITO: {score_result.verdict}  (score {score_result.total_score}/100)")
    print("=" * 70)
    print(f"Assunto     : {parsed_email.headers.get('subject', '')}")
    print(f"De          : {parsed_email.headers['from']['raw']}")
    print(f"Reply-To    : {parsed_email.headers['reply_to']['raw'] or '(ausente)'}")
    print(f"Return-Path : {parsed_email.headers['return_path']['raw'] or '(ausente)'}")
    print()
    print("-- Indicadores --")
    if not score_result.hits:
        print("Nenhum indicador de risco disparado.")
    for hit in sorted(score_result.hits, key=lambda h: -h.weight):
        print(f"  [+{hit.weight:>2}] {hit.rule_id}: {hit.description}")
    print()
    print("-- URLs --")
    for uf in url_findings:
        flags = []
        if uf.typosquat_of:
            flags.append(f"typosquat de {uf.typosquat_of}")
        if uf.anchor_mismatch:
            flags.append("texto!=destino")
        if uf.is_shortener:
            flags.append("encurtador")
        print(f"  {uf.domain} -- {', '.join(flags) or 'sem sinalizacoes'}")
    if parsed_email.attachments:
        print()
        print("-- Anexos --")
        for att in parsed_email.attachments:
            print(f"  {att.filename} ({att.content_type}) sha256={att.sha256}")


def build_json_report(parsed_email, header_findings, url_findings, score_result,
                       vt_domain_results=None, vt_url_results=None, vt_ip_results=None,
                       whois_results=None) -> dict:
    vt_domain_results = vt_domain_results or {}
    vt_url_results = vt_url_results or {}
    vt_ip_results = vt_ip_results or {}
    whois_results = whois_results or {}

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "verdict": score_result.verdict,
        "score": score_result.total_score,
        "email": {
            "subject": parsed_email.headers.get("subject", ""),
            "from": parsed_email.headers["from"],
            "reply_to": parsed_email.headers["reply_to"],
            "return_path": parsed_email.headers["return_path"],
            "date": parsed_email.headers.get("date", ""),
            "message_id": parsed_email.headers.get("message_id", ""),
        },
        "auth_results": {
            "spf": header_findings.auth_results.spf,
            "dkim": header_findings.auth_results.dkim,
            "dmarc": header_findings.auth_results.dmarc,
            "spf_dns_record": header_findings.spf_dns_record,
            "dmarc_dns_record": header_findings.dmarc_dns_record,
            "dmarc_policy": header_findings.dmarc_policy,
        },
        "indicators": [
            {"rule_id": h.rule_id, "weight": h.weight, "description": h.description, "detail": h.detail}
            for h in score_result.hits
        ],
        "urls": [
            {
                "url": uf.url,
                "domain": uf.domain,
                "typosquat_of": uf.typosquat_of,
                "anchor_mismatch": uf.anchor_mismatch,
                "is_shortener": uf.is_shortener,
                "is_punycode": uf.is_punycode,
                "is_ip_literal": uf.is_ip_literal,
                "suspicious_tld": uf.suspicious_tld,
                "virustotal": {
                    "malicious": vt_url_results[uf.url].malicious,
                    "suspicious": vt_url_results[uf.url].suspicious,
                } if uf.url in vt_url_results and vt_url_results[uf.url].checked else None,
            }
            for uf in url_findings
        ],
        "domains_reputation": {
            domain: {
                "virustotal_malicious": v.malicious,
                "virustotal_suspicious": v.suspicious,
                "checked": v.checked,
                "error": v.error,
            }
            for domain, v in vt_domain_results.items()
        },
        "whois": {
            domain: {
                "age_days": w.age_days,
                "creation_date": w.creation_date.isoformat() if w.creation_date else None,
                "registrar": w.registrar,
                "checked": w.checked,
                "error": w.error,
            }
            for domain, w in whois_results.items()
        },
        "attachments": [
            {"filename": a.filename, "content_type": a.content_type, "sha256": a.sha256, "size_bytes": a.size_bytes}
            for a in parsed_email.attachments
        ],
        "received_ips": header_findings.received_ips,
        "notes": header_findings.notes,
    }


def save_json_report(report_dict: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2, ensure_ascii=False)


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="utf-8">
<title>Relatorio de analise de phishing</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; margin: 2rem; color: #1a1a1a; }}
  .verdict {{ padding: 1rem 1.5rem; border-radius: 8px; font-size: 1.2rem; font-weight: bold; color: #fff; }}
  .high {{ background: #c0392b; }}
  .medium {{ background: #d68910; }}
  .low {{ background: #2471a3; }}
  .clean {{ background: #229954; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1.2rem; }}
  th, td {{ border: 1px solid #ddd; padding: 0.5rem 0.7rem; text-align: left; font-size: 0.92rem; }}
  th {{ background: #f4f4f4; }}
  h2 {{ margin-top: 2rem; }}
  code {{ background: #f4f4f4; padding: 0.1rem 0.35rem; border-radius: 4px; }}
</style>
</head>
<body>
  <h1>Relatorio de analise de phishing</h1>
  <div class="verdict {verdict_class}">{verdict} — score {score}/100</div>

  <h2>Metadados</h2>
  <table>
    <tr><th>Assunto</th><td>{subject}</td></tr>
    <tr><th>De</th><td>{from_raw}</td></tr>
    <tr><th>Reply-To</th><td>{reply_to}</td></tr>
    <tr><th>Return-Path</th><td>{return_path}</td></tr>
    <tr><th>Data</th><td>{date}</td></tr>
  </table>

  <h2>Indicadores</h2>
  <table>
    <tr><th>Regra</th><th>Peso</th><th>Descricao</th></tr>
    {indicator_rows}
  </table>

  <h2>URLs</h2>
  <table>
    <tr><th>Dominio</th><th>Sinalizacoes</th></tr>
    {url_rows}
  </table>

  <h2>Anexos</h2>
  <table>
    <tr><th>Nome</th><th>Tipo</th><th>SHA256</th></tr>
    {attachment_rows}
  </table>

  <p style="margin-top:2rem;font-size:0.8rem;color:#888;">
    Gerado em {generated_at} — ferramenta de apoio, nao substitui analise manual.
  </p>
</body>
</html>
"""


def build_html_report(parsed_email, header_findings, url_findings, score_result) -> str:
    verdict_class = {"ALTO": "high", "SUSPEITO": "medium", "BAIXO": "low"}.get(
        score_result.verdict.split()[0], "clean"
    )

    indicator_rows = "".join(
        f"<tr><td><code>{h.rule_id}</code></td><td>+{h.weight}</td><td>{h.description}</td></tr>"
        for h in sorted(score_result.hits, key=lambda h: -h.weight)
    ) or "<tr><td colspan='3'>Nenhum indicador disparado.</td></tr>"

    url_rows = "".join(
        f"<tr><td>{uf.domain}</td><td>{'typosquat de ' + uf.typosquat_of if uf.typosquat_of else ''} "
        f"{'texto≠destino' if uf.anchor_mismatch else ''} {'encurtador' if uf.is_shortener else ''}</td></tr>"
        for uf in url_findings
    ) or "<tr><td colspan='2'>Nenhuma URL encontrada.</td></tr>"

    attachment_rows = "".join(
        f"<tr><td>{a.filename}</td><td>{a.content_type}</td><td><code>{a.sha256}</code></td></tr>"
        for a in parsed_email.attachments
    ) or "<tr><td colspan='3'>Nenhum anexo.</td></tr>"

    return _HTML_TEMPLATE.format(
        verdict_class=verdict_class,
        verdict=score_result.verdict,
        score=score_result.total_score,
        subject=parsed_email.headers.get("subject", ""),
        from_raw=parsed_email.headers["from"]["raw"],
        reply_to=parsed_email.headers["reply_to"]["raw"] or "(ausente)",
        return_path=parsed_email.headers["return_path"]["raw"] or "(ausente)",
        date=parsed_email.headers.get("date", ""),
        indicator_rows=indicator_rows,
        url_rows=url_rows,
        attachment_rows=attachment_rows,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


def save_html_report(html: str, path: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
