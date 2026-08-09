"""
url_analysis.py
Analisa cada URL encontrada no e-mail: extrai o domínio, verifica se é
IP puro, se usa punycode (homograph attack), se é encurtador, se o TLD é
de risco elevado, e faz scoring de "parecido com marca conhecida"
(typosquatting) usando distância de edição (Levenshtein), sem depender
de bibliotecas externas de fuzzy-matching.

Também compara o domínio do href real com o texto-âncora exibido, que é
um dos indicadores mais confiáveis de phishing em HTML.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

from analyzer.parser import extract_domain
from analyzer.header_analysis import KNOWN_BRANDS

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorte.st", "bl.ink", "rb.gy", "shorturl.at",
    "s.id", "v.gd", "tiny.cc", "lnkd.in",
}

# TLDs historicamente muito associados a campanhas de phishing/spam por
# terem registro barato ou gratuito. Não é prova de nada sozinho -- é só
# mais um ponto no score.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "work", "link",
    "loan", "win", "review", "country", "kim", "science", "party", "gdn",
    "zip", "mov",
}


@dataclass
class UrlFinding:
    url: str
    domain: str
    is_ip_literal: bool = False
    is_punycode: bool = False
    is_shortener: bool = False
    suspicious_tld: bool = False
    typosquat_of: str = ""       # nome da marca que parece estar sendo imitada
    typosquat_distance: int = -1  # distância de edição até o domínio legítimo
    anchor_mismatch: bool = False  # texto exibido aponta para domínio diferente do href real
    anchor_text: str = ""


def levenshtein(a: str, b: str) -> int:
    """Distância de edição clássica (programação dinâmica, O(n*m))."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr_row = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr_row[j] = min(
                prev_row[j] + 1,        # deleção
                curr_row[j - 1] + 1,    # inserção
                prev_row[j - 1] + cost,  # substituição
            )
        prev_row = curr_row
    return prev_row[-1]


def _registrable_part(domain: str) -> str:
    """Aproximação simples do domínio 'base' sem subdomínios (não usa PSL completa)."""
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    return ".".join(parts[-2:])


def check_typosquatting(domain: str, max_distance: int = 2):
    """
    Compara o domínio contra a lista de marcas conhecidas (mesma lista usada
    para detectar display-name spoofing). Dois padrões são cobertos:

      1) Erro de digitação clássico: distância de edição pequena entre o
         domínio e o nome da marca (ex.: 'itaU.com', 'ita-u.com').
      2) Marca legítima embutida no domínio como isca, mas o domínio
         REGISTRÁVEL real é outro (ex.: 'itau.com.br.validacao-segura.net',
         'login-itau-seguro.net'). Aqui a distância de edição não faz
         sentido como métrica, então reportamos distância 0 (== "contém a
         marca literalmente, mas não é o domínio da marca").

    Retorna (nome_da_marca, distancia) ou ("", -1) se nada suspeito.
    """
    reg_domain = _registrable_part(domain)

    all_legit = {d for domains in KNOWN_BRANDS.values() for d in domains}
    if domain in all_legit or reg_domain in all_legit:
        return "", -1

    candidate_base = reg_domain.split(".")[0]

    # Padrão 2 primeiro: marca aparece literalmente embutida no domínio,
    # mas o domínio registrável não é da marca -- isso é phishing quase
    # certo, independentemente de distância de edição.
    for brand, legit_domains in KNOWN_BRANDS.items():
        legit_base = legit_domains[0].split(".")[0]
        if len(legit_base) >= 3 and legit_base in domain:
            return brand, 0

    # Padrão 1: erro de digitação -- distância de edição pequena entre o
    # domínio candidato e o nome-base da marca.
    best_brand, best_distance = "", 999
    for brand, legit_domains in KNOWN_BRANDS.items():
        legit_base = legit_domains[0].split(".")[0]
        dist = levenshtein(candidate_base, legit_base)
        if dist <= max_distance and dist < best_distance:
            best_brand, best_distance = brand, dist

    return (best_brand, best_distance) if best_brand else ("", -1)


def analyze_url(url: str, anchor_text: str = "") -> UrlFinding:
    domain = extract_domain(url)
    parsed = urlparse(url)

    finding = UrlFinding(url=url, domain=domain, anchor_text=anchor_text)

    finding.is_ip_literal = domain.replace(".", "").isdigit()
    finding.is_punycode = "xn--" in domain
    finding.is_shortener = domain in URL_SHORTENERS
    tld = domain.split(".")[-1] if "." in domain else ""
    finding.suspicious_tld = tld in SUSPICIOUS_TLDS

    brand, distance = check_typosquatting(domain)
    finding.typosquat_of = brand
    finding.typosquat_distance = distance

    if anchor_text:
        anchor_lower = anchor_text.lower().strip()
        looks_like_url_or_domain = "." in anchor_lower and " " not in anchor_lower
        if looks_like_url_or_domain:
            anchor_domain = extract_domain(anchor_lower)
            if anchor_domain and anchor_domain != domain:
                finding.anchor_mismatch = True

    return finding


def analyze_all_urls(urls_with_anchor: list) -> list:
    seen = set()
    findings = []
    for url, anchor in urls_with_anchor:
        normalized = url if url.lower().startswith("http") else f"http://{url}"
        key = (normalized, anchor)
        if key in seen:
            continue
        seen.add(key)
        findings.append(analyze_url(normalized, anchor))
    return findings
