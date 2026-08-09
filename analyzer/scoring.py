"""
scoring.py
Agrega os achados de header_analysis, url_analysis e reputation em um
score único, ponderado, com veredito final. A ideia não é substituir o
julgamento do analista -- é organizar os indicadores e priorizar o que
olhar primeiro, do jeito que você já faz manualmente ao cruzar
Authentication-Results + VirusTotal + bom senso.

Cada regra tem um peso. Pesos maiores = indicadores historicamente mais
confiáveis de phishing. Ajuste a gosto conforme o seu contexto (os pesos
aqui refletem heurísticas comuns de mercado, não uma verdade absoluta).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

DANGEROUS_ATTACHMENT_EXT = {
    "exe", "scr", "js", "vbs", "bat", "cmd", "ps1", "jar", "hta", "msi",
    "lnk", "docm", "xlsm", "pptm", "wsf", "vbe", "chm", "iso", "img",
}

URGENCY_KEYWORDS = [
    "urgente", "última chance", "ação necessária", "conta será bloqueada",
    "conta suspensa", "confirme seus dados", "verifique agora",
    "clique aqui", "acesso será cancelado", "regularize", "pendência",
    "você ganhou", "prêmio", "faça login imediatamente", "atualize seus dados",
    "sua senha expira", "detectamos uma atividade", "evite o cancelamento",
]


@dataclass
class RuleHit:
    rule_id: str
    description: str
    weight: int
    detail: str = ""


@dataclass
class ScoreResult:
    total_score: int = 0
    verdict: str = ""
    hits: list = field(default_factory=list)  # list[RuleHit]

    def add(self, rule_id, description, weight, detail=""):
        self.hits.append(RuleHit(rule_id, description, weight, detail))
        self.total_score += weight


def _verdict_from_score(score: int) -> str:
    if score >= 55:
        return "ALTO RISCO — phishing provável"
    if score >= 25:
        return "SUSPEITO — requer análise manual"
    if score > 0:
        return "BAIXO RISCO — poucos indicadores, mas não ignorar"
    return "SEM INDICADORES — nenhum sinal relevante encontrado"


def score_urgency_language(body_text: str, body_html: str) -> tuple[int, list]:
    combined = f"{body_text}\n{body_html}".lower()
    matched = [kw for kw in URGENCY_KEYWORDS if kw in combined]
    return len(matched), matched


def score_email(
    parsed_email,
    header_findings,
    url_findings: list,
    vt_domain_results: dict | None = None,
    vt_url_results: dict | None = None,
    vt_ip_results: dict | None = None,
    whois_results: dict | None = None,
) -> ScoreResult:
    vt_domain_results = vt_domain_results or {}
    vt_url_results = vt_url_results or {}
    vt_ip_results = vt_ip_results or {}
    whois_results = whois_results or {}

    result = ScoreResult()
    auth = header_findings.auth_results

    # --- Autenticação de e-mail ---------------------------------------
    if auth.spf in ("fail", "softfail"):
        result.add("SPF_FAIL", f"SPF resultou em '{auth.spf}'", 15, str(auth.raw_headers))
    elif auth.spf == "none":
        result.add("SPF_NONE", "Nenhum resultado de SPF encontrado no cabeçalho", 5)

    if auth.dkim == "fail":
        result.add("DKIM_FAIL", "DKIM resultou em 'fail'", 15)
    elif auth.dkim != "pass" and not parsed_email.headers.get("dkim_signature_present"):
        # Só flagamos ausência de assinatura quando ela de fato não está lá
        # E o resultado relatado não foi "pass" -- evita ruído quando o
        # servidor já validou o DKIM mas a cópia recebida não traz o header.
        result.add("DKIM_NONE", "E-mail não possui assinatura DKIM", 8)

    if auth.dmarc == "fail":
        result.add("DMARC_FAIL", "DMARC resultou em 'fail'", 15)

    # Regras baseadas no registro DMARC publicado no DNS só fazem sentido
    # quando a consulta DNS realmente foi feita (modo --offline não consulta).
    if header_findings.dns_lookups_performed and auth.dmarc != "pass":
        if header_findings.dmarc_dns_record and header_findings.dmarc_policy in ("none", ""):
            result.add("DMARC_WEAK_POLICY", "Domínio publica DMARC mas com política 'none'", 5)
        elif not header_findings.dmarc_dns_record:
            result.add("DMARC_ABSENT", "Domínio remetente não publica registro DMARC", 6)

    # --- Identidade do remetente -----------------------------------
    if header_findings.reply_to_mismatch:
        result.add("REPLY_TO_MISMATCH", "Reply-To diferente do domínio do From", 12)

    if header_findings.return_path_mismatch:
        result.add("RETURN_PATH_MISMATCH", "Return-Path diferente do domínio do From", 8)

    if header_findings.display_name_brand_spoof:
        result.add(
            "DISPLAY_NAME_SPOOF",
            f"Nome de exibição imita a marca '{header_findings.display_name_brand_spoof}'",
            20,
        )

    # --- URLs -----------------------------------------------------
    for uf in url_findings:
        if uf.typosquat_of:
            if uf.typosquat_distance == 0:
                desc = (
                    f"Domínio '{uf.domain}' contém a marca '{uf.typosquat_of}' "
                    f"embutida como isca, mas não é o domínio oficial"
                )
            else:
                desc = (
                    f"Domínio '{uf.domain}' parece erro de digitação de "
                    f"'{uf.typosquat_of}' (distância de edição={uf.typosquat_distance})"
                )
            result.add("TYPOSQUATTING", desc, 18, uf.url)
        if uf.anchor_mismatch:
            result.add(
                "ANCHOR_MISMATCH",
                f"Texto do link ('{uf.anchor_text}') não corresponde ao destino real ({uf.domain})",
                14,
                uf.url,
            )
        if uf.is_punycode:
            result.add("PUNYCODE_DOMAIN", f"Domínio usa punycode (possível homograph): {uf.domain}", 12, uf.url)
        if uf.is_ip_literal:
            result.add("IP_LITERAL_URL", f"Link aponta direto para um IP: {uf.domain}", 10, uf.url)
        if uf.is_shortener:
            result.add("URL_SHORTENER", f"Link usa encurtador ({uf.domain}), destino real ofuscado", 6, uf.url)
        if uf.suspicious_tld:
            result.add("SUSPICIOUS_TLD", f"Domínio usa TLD associado a abuso: .{uf.domain.split('.')[-1]}", 5, uf.url)

    # --- Reputação externa (VirusTotal) -----------------------------
    for domain, verdict in vt_domain_results.items():
        if verdict.checked and verdict.is_flagged:
            result.add(
                "VT_DOMAIN_FLAGGED",
                f"VirusTotal: {domain} marcado como malicioso/suspeito por "
                f"{verdict.malicious + verdict.suspicious} motor(es)",
                min(30, 10 + (verdict.malicious + verdict.suspicious) * 2),
            )

    for url, verdict in vt_url_results.items():
        if verdict.checked and verdict.is_flagged:
            result.add(
                "VT_URL_FLAGGED",
                f"VirusTotal: URL marcada como maliciosa/suspeita por "
                f"{verdict.malicious + verdict.suspicious} motor(es)",
                min(30, 10 + (verdict.malicious + verdict.suspicious) * 2),
                url,
            )

    for ip, verdict in vt_ip_results.items():
        if verdict.checked and verdict.is_flagged:
            result.add(
                "VT_IP_FLAGGED",
                f"VirusTotal: IP {ip} da cadeia Received marcado como malicioso/suspeito",
                12,
            )

    # --- WHOIS / idade de domínio -----------------------------------
    for domain, w in whois_results.items():
        if w.checked and w.age_days is not None:
            if w.age_days < 30:
                result.add("DOMAIN_VERY_NEW", f"Domínio {domain} registrado há {w.age_days} dia(s)", 20)
            elif w.age_days < 180:
                result.add("DOMAIN_RECENT", f"Domínio {domain} registrado há {w.age_days} dias (< 6 meses)", 8)

    # --- Anexos -----------------------------------------------------
    for att in parsed_email.attachments:
        ext = att.filename.rsplit(".", 1)[-1].lower() if "." in att.filename else ""
        double_ext = bool(re.search(r"\.\w{2,4}\.\w{2,4}$", att.filename))
        if ext in DANGEROUS_ATTACHMENT_EXT:
            result.add(
                "DANGEROUS_ATTACHMENT",
                f"Anexo com extensão de risco: {att.filename} ({att.content_type})",
                20,
                att.sha256,
            )
        elif double_ext:
            result.add(
                "DOUBLE_EXTENSION_ATTACHMENT",
                f"Anexo com extensão dupla suspeita: {att.filename}",
                15,
                att.sha256,
            )

    # --- Linguagem de urgência no corpo ------------------------------
    n_matches, matched_kw = score_urgency_language(parsed_email.body_text, parsed_email.body_html)
    if n_matches:
        result.add(
            "URGENCY_LANGUAGE",
            f"{n_matches} termo(s) de pressão/urgência encontrados no corpo",
            min(15, n_matches * 4),
            ", ".join(matched_kw),
        )

    result.total_score = min(result.total_score, 100)
    result.verdict = _verdict_from_score(result.total_score)
    return result
