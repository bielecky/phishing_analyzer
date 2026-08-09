#!/usr/bin/env python3
"""
Phishing Email Analyzer -- CLI

Uso básico:
    python main.py --file suspeito.eml

Com checagem de reputação (VirusTotal + WHOIS):
    export VT_API_KEY="sua_chave_aqui"
    python main.py --file suspeito.eml --check-reputation

Somente heurísticas locais, sem nenhuma chamada externa:
    python main.py --file suspeito.eml --offline

Salvando relatórios:
    python main.py --file suspeito.eml --json output/relatorio.json --html output/relatorio.html
"""

from __future__ import annotations

import argparse
import os
import sys

from analyzer import parser as email_parser
from analyzer import header_analysis
from analyzer import url_analysis
from analyzer import reputation
from analyzer import scoring
from analyzer import report


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Analisa um e-mail (.eml) em busca de indicadores de phishing."
    )
    p.add_argument("--file", "-f", help="Caminho do arquivo .eml a analisar. Se omitido, lê da stdin.")
    p.add_argument(
        "--offline", action="store_true",
        help="Não faz nenhuma chamada de rede (nem DNS, nem VirusTotal, nem WHOIS). "
             "Só heurísticas locais de header/URL/anexo."
    )
    p.add_argument(
        "--check-reputation", action="store_true",
        help="Consulta VirusTotal para os domínios/URLs/IPs encontrados. Requer VT_API_KEY "
             "(env var ou --vt-key)."
    )
    p.add_argument("--vt-key", default=os.environ.get("VT_API_KEY", ""), help="Chave de API do VirusTotal.")
    p.add_argument(
        "--abuseipdb-key", default=os.environ.get("ABUSEIPDB_API_KEY", ""),
        help="Chave de API do AbuseIPDB (opcional, checa reputação dos IPs da cadeia Received)."
    )
    p.add_argument("--no-whois", action="store_true", help="Pula a consulta WHOIS de idade de domínio.")
    p.add_argument("--json", help="Caminho para salvar o relatório em JSON.")
    p.add_argument("--html", help="Caminho para salvar o relatório em HTML.")
    p.add_argument("--quiet", action="store_true", help="Não imprime o relatório no console (útil com --json/--html).")
    return p


def main(argv=None):
    args = build_arg_parser().parse_args(argv)

    if args.file:
        parsed = email_parser.load_email(args.file)
    else:
        raw = sys.stdin.buffer.read()
        if not raw:
            print("Nenhum arquivo informado (--file) e stdin vazio.", file=sys.stderr)
            return 1
        parsed = email_parser.parse_email_bytes(raw)

    do_dns = not args.offline
    header_findings = header_analysis.analyze_headers(parsed, do_dns_lookups=do_dns)
    url_findings = url_analysis.analyze_all_urls(parsed.urls_with_anchor)

    vt_domain_results, vt_url_results, vt_ip_results, whois_results = {}, {}, {}, {}

    from_domain = header_analysis.extract_domain_safe(parsed.headers["from"]["email"])

    if not args.offline and args.check_reputation:
        if not args.vt_key:
            print("Aviso: --check-reputation foi passado mas nenhuma VT_API_KEY foi encontrada. "
                  "Pulando checagem no VirusTotal.", file=sys.stderr)
        else:
            vt = reputation.VirusTotalClient(args.vt_key)
            domains_to_check = {from_domain} | {uf.domain for uf in url_findings}
            domains_to_check.discard("")
            for domain in domains_to_check:
                vt_domain_results[domain] = vt.check_domain(domain)

            for uf in url_findings:
                vt_url_results[uf.url] = vt.check_url(uf.url)

            for ip in header_findings.received_ips:
                vt_ip_results[ip] = vt.check_ip(ip)

        if args.abuseipdb_key and header_findings.received_ips:
            abuse_client = reputation.AbuseIpDbClient(args.abuseipdb_key)
            for ip in header_findings.received_ips:
                verdict = abuse_client.check_ip(ip)
                if verdict.checked and verdict.abuse_score and verdict.abuse_score >= 50:
                    header_findings.notes.append(
                        f"AbuseIPDB: IP {ip} com confidence score {verdict.abuse_score}"
                    )

    if not args.offline and not args.no_whois:
        whois_client = reputation.WhoisClient()
        domains_to_check = {from_domain} | {uf.domain for uf in url_findings}
        domains_to_check.discard("")
        for domain in domains_to_check:
            whois_results[domain] = whois_client.lookup(domain)

    score_result = scoring.score_email(
        parsed, header_findings, url_findings,
        vt_domain_results=vt_domain_results,
        vt_url_results=vt_url_results,
        vt_ip_results=vt_ip_results,
        whois_results=whois_results,
    )

    if not args.quiet:
        report.print_console_report(parsed, header_findings, url_findings, score_result,
                                     vt_domain_results, whois_results)

    if args.json:
        report_dict = report.build_json_report(
            parsed, header_findings, url_findings, score_result,
            vt_domain_results, vt_url_results, vt_ip_results, whois_results,
        )
        report.save_json_report(report_dict, args.json)
        print(f"\nRelatório JSON salvo em: {args.json}")

    if args.html:
        html = report.build_html_report(parsed, header_findings, url_findings, score_result)
        report.save_html_report(html, args.html)
        print(f"Relatório HTML salvo em: {args.html}")

    # Código de saída útil para automação (ex.: pipeline de triagem)
    if score_result.total_score >= 55:
        return 2
    if score_result.total_score >= 25:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
