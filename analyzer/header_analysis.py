"""
header_analysis.py
Analisa os headers do e-mail em busca dos sinais clássicos de spoofing:

  - Resultado de SPF/DKIM/DMARC (via header Authentication-Results, que é
    calculado pelo servidor de e-mail receptor -- é o mesmo dado que
    ferramentas como Cisco CES/Proofpoint expõem no dia a dia de um SOC)
  - Registro SPF/DMARC publicado no DNS do domínio do remetente (consulta
    ativa, útil quando o Authentication-Results não veio ou é de confiar)
  - Divergência entre From / Reply-To / Return-Path (redirecionamento de
    resposta é uma das táticas mais usadas em BEC e phishing de credencial)
  - "Display name spoofing" (nome exibido de uma marca/empresa conhecida,
    mas domínio do e-mail não tem nada a ver, ex.: "Itaú" <suporte@xyz123.com>)
  - IPs presentes na cadeia de Received, para eventual checagem de reputação
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import dns.resolver

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Termos que, quando aparecem no display name mas o domínio do e-mail não
# bate com a marca, são fortes candidatos a spoofing. Lista pensada para o
# cenário de phishing bancário/corporativo no Brasil -- pode/deve ser
# expandida conforme os casos que você vir no dia a dia do SOC.
KNOWN_BRANDS = {
    "itau": ["itau.com.br"],
    "bradesco": ["bradesco.com.br"],
    "santander": ["santander.com.br"],
    "caixa": ["caixa.gov.br"],
    "banco do brasil": ["bb.com.br"],
    "nubank": ["nubank.com.br"],
    "inter": ["bancointer.com.br"],
    "mercado livre": ["mercadolivre.com.br", "mercadopago.com.br"],
    "correios": ["correios.com.br"],
    "receita federal": ["gov.br"],
    "serasa": ["serasa.com.br"],
    "microsoft": ["microsoft.com", "outlook.com", "office.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "paypal": ["paypal.com"],
    "claro": ["claro.com.br"],
    "embratel": ["embratel.com.br"],
}


@dataclass
class AuthResult:
    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"
    raw_headers: list = field(default_factory=list)


@dataclass
class HeaderFindings:
    auth_results: AuthResult
    spf_dns_record: str = ""
    dmarc_dns_record: str = ""
    dmarc_policy: str = ""
    reply_to_mismatch: bool = False
    return_path_mismatch: bool = False
    display_name_brand_spoof: str = ""  # nome da marca detectada, se houver
    received_ips: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    dns_lookups_performed: bool = False


def parse_authentication_results(auth_headers: list[str]) -> AuthResult:
    """
    Extrai spf=/dkim=/dmarc= do(s) header(s) Authentication-Results.
    Pode haver mais de um header, ou mais de uma menção ao mesmo mecanismo
    (ex.: cadeias de reencaminhamento), então coletamos todos os valores
    encontrados e ficamos com o PIOR relatado (fail > softfail > neutral >
    none > pass). Importante: o valor inicial é "não encontrado" (None),
    não "none" -- "none" é, ele próprio, um resultado válido que pode
    aparecer no header, e não pode ser o que impede um "pass" de contar.
    """
    result = AuthResult(spf="none", dkim="none", dmarc="none", raw_headers=list(auth_headers))
    severity = {"fail": 5, "softfail": 4, "neutral": 3, "none": 2, "pass": 1}

    found = {"spf": [], "dkim": [], "dmarc": []}
    for header in auth_headers:
        for mechanism in ("spf", "dkim", "dmarc"):
            for m in re.finditer(rf"\b{mechanism}=(\w+)", header, re.IGNORECASE):
                found[mechanism].append(m.group(1).lower())

    for mechanism in ("spf", "dkim", "dmarc"):
        values = found[mechanism]
        if values:
            worst = max(values, key=lambda v: severity.get(v, 0))
            setattr(result, mechanism, worst)

    return result


def check_spf_dns(domain: str) -> str:
    """Consulta o registro SPF (TXT v=spf1) publicado no DNS do domínio."""
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode(errors="ignore") if hasattr(rdata, "strings") else str(rdata)
            if txt.lower().startswith("v=spf1") or "v=spf1" in txt.lower():
                return txt
    except Exception:
        pass
    return ""


def check_dmarc_dns(domain: str) -> tuple[str, str]:
    """Consulta o registro DMARC em _dmarc.<domain> e extrai a policy (p=)."""
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode(errors="ignore") if hasattr(rdata, "strings") else str(rdata)
            if "v=dmarc1" in txt.lower():
                m = re.search(r"p=(\w+)", txt, re.IGNORECASE)
                policy = m.group(1).lower() if m else "none"
                return txt, policy
    except Exception:
        pass
    return "", "none"


def detect_display_name_spoof(display_name: str, from_domain: str) -> str:
    """
    Se o nome de exibição menciona uma marca conhecida mas o domínio do
    remetente não é um dos domínios legítimos daquela marca, retorna o
    nome da marca suspeita. Caso contrário retorna string vazia.
    """
    if not display_name:
        return ""
    name_lower = display_name.lower()
    for brand, legit_domains in KNOWN_BRANDS.items():
        if brand in name_lower:
            if not any(from_domain.endswith(d) for d in legit_domains):
                return brand
    return ""


def extract_received_ips(received_chain: list[str]) -> list[str]:
    ips = []
    for header in received_chain:
        for ip in _IP_RE.findall(header):
            if ip not in ips:
                ips.append(ip)
    return ips


def analyze_headers(parsed_email, do_dns_lookups: bool = True) -> HeaderFindings:
    headers = parsed_email.headers
    auth_results = parse_authentication_results(headers.get("authentication_results", []))

    from_domain = extract_domain_safe(headers["from"]["email"])
    reply_to_email = headers["reply_to"]["email"]
    return_path_email = headers["return_path"]["email"]

    findings = HeaderFindings(auth_results=auth_results)

    if reply_to_email and extract_domain_safe(reply_to_email) != from_domain:
        findings.reply_to_mismatch = True
        findings.notes.append(
            f"Reply-To ({reply_to_email}) aponta para domínio diferente do From ({from_domain})"
        )

    if return_path_email and extract_domain_safe(return_path_email) != from_domain:
        findings.return_path_mismatch = True
        findings.notes.append(
            f"Return-Path ({return_path_email}) aponta para domínio diferente do From ({from_domain})"
        )

    findings.display_name_brand_spoof = detect_display_name_spoof(
        headers["from"]["display_name"], from_domain
    )
    if findings.display_name_brand_spoof:
        findings.notes.append(
            f"Nome de exibição menciona '{findings.display_name_brand_spoof}' "
            f"mas domínio remetente ({from_domain}) não pertence à marca"
        )

    findings.received_ips = extract_received_ips(parsed_email.received_chain)

    if do_dns_lookups and from_domain:
        findings.dns_lookups_performed = True
        findings.spf_dns_record = check_spf_dns(from_domain)
        findings.dmarc_dns_record, findings.dmarc_policy = check_dmarc_dns(from_domain)
        if not findings.spf_dns_record:
            findings.notes.append(f"Domínio {from_domain} não publica registro SPF")
        if not findings.dmarc_dns_record:
            findings.notes.append(f"Domínio {from_domain} não publica registro DMARC")
        elif findings.dmarc_policy in ("none", ""):
            findings.notes.append("Política DMARC é 'none' (não força rejeição/quarentena)")

    return findings


def extract_domain_safe(email_addr: str) -> str:
    if "@" not in email_addr:
        return ""
    return email_addr.rsplit("@", 1)[-1].lower().strip()
