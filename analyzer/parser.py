"""
parser.py
Responsável por ler um arquivo .eml (ou texto bruto de e-mail) e extrair,
de forma estruturada, tudo que os outros módulos vão precisar analisar:
headers, corpo (texto/html), URLs encontradas e anexos.

Não faz nenhuma checagem de reputação/heurística aqui -- só extração.
Isso mantém o parser reutilizável e fácil de testar isoladamente.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from typing import Optional
from urllib.parse import urlparse

try:
    from bs4 import BeautifulSoup
    _HAS_BS4 = True
except ImportError:
    _HAS_BS4 = False

# Regex de fallback para achar URLs em texto puro (sem depender de BeautifulSoup)
_URL_RE = re.compile(
    r"""(?i)\b((?:https?://|www\.)[^\s<>"'\)\]]+)"""
)


@dataclass
class Attachment:
    filename: str
    content_type: str
    size_bytes: int
    sha256: str


@dataclass
class ParsedEmail:
    raw_bytes: bytes
    headers: dict = field(default_factory=dict)
    received_chain: list = field(default_factory=list)
    body_text: str = ""
    body_html: str = ""
    urls: list = field(default_factory=list)
    urls_with_anchor: list = field(default_factory=list)  # [(url, texto_visivel)]
    attachments: list = field(default_factory=list)
    message: Optional[EmailMessage] = None


def load_email(path: str) -> ParsedEmail:
    """Carrega um arquivo .eml do disco e retorna um ParsedEmail."""
    with open(path, "rb") as f:
        raw = f.read()
    return parse_email_bytes(raw)


def parse_email_bytes(raw: bytes) -> ParsedEmail:
    """Faz o parsing de bytes brutos de um e-mail (formato RFC 822 / .eml)."""
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    headers = _extract_headers(msg)
    received_chain = msg.get_all("Received", [])
    body_text, body_html = _extract_bodies(msg)
    urls, urls_with_anchor = _extract_urls(body_text, body_html)
    attachments = _extract_attachments(msg)

    return ParsedEmail(
        raw_bytes=raw,
        headers=headers,
        received_chain=list(received_chain),
        body_text=body_text,
        body_html=body_html,
        urls=urls,
        urls_with_anchor=urls_with_anchor,
        attachments=attachments,
        message=msg,
    )


def _extract_headers(msg: EmailMessage) -> dict:
    """
    Extrai os headers relevantes para investigação de phishing.
    Guarda tanto o valor cru quanto endereços já parseados (nome + email)
    para From/Reply-To/Return-Path, que é onde mora boa parte da fraude.
    """
    def parsed_addr(header_name):
        raw = msg.get(header_name, "")
        name, addr = parseaddr(raw)
        return {"raw": raw, "display_name": name, "email": addr.lower() if addr else ""}

    return {
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "from": parsed_addr("From"),
        "reply_to": parsed_addr("Reply-To"),
        "return_path": parsed_addr("Return-Path"),
        "to": [addr.lower() for _, addr in getaddresses(msg.get_all("To", []))],
        "authentication_results": msg.get_all("Authentication-Results", []),
        "received_spf": msg.get("Received-SPF", ""),
        "x_originating_ip": msg.get("X-Originating-IP", ""),
        "dkim_signature_present": msg.get("DKIM-Signature") is not None,
    }


def _extract_bodies(msg: EmailMessage) -> tuple[str, str]:
    """Separa corpo texto-plano e corpo HTML, percorrendo partes multipart."""
    text_parts, html_parts = [], []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            if "attachment" in disp:
                continue
            try:
                content = part.get_content()
            except Exception:
                continue
            if ctype == "text/plain" and isinstance(content, str):
                text_parts.append(content)
            elif ctype == "text/html" and isinstance(content, str):
                html_parts.append(content)
    else:
        ctype = msg.get_content_type()
        try:
            content = msg.get_content()
        except Exception:
            content = ""
        if ctype == "text/html":
            html_parts.append(content if isinstance(content, str) else "")
        else:
            text_parts.append(content if isinstance(content, str) else "")

    return "\n".join(text_parts), "\n".join(html_parts)


def _extract_urls(body_text: str, body_html: str) -> tuple[list, list]:
    """
    Retorna (lista_de_urls_unicas, lista_de_pares_url_texto_ancora).
    O segundo é importante para detectar phishing clássico: link exibido
    diz "meubanco.com.br" mas o href real aponta para outro domínio.
    """
    urls_with_anchor = []

    if body_html and _HAS_BS4:
        soup = BeautifulSoup(body_html, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            anchor_text = a.get_text(strip=True)
            if href.lower().startswith(("http://", "https://", "www.")):
                urls_with_anchor.append((href, anchor_text))
    elif body_html:
        # fallback sem bs4: só extrai via regex, sem texto-âncora
        for m in _URL_RE.findall(body_html):
            urls_with_anchor.append((m, ""))

    # URLs soltas no corpo texto-plano também entram (sem âncora)
    for m in _URL_RE.findall(body_text):
        urls_with_anchor.append((m, ""))

    seen = set()
    unique_urls = []
    for url, _ in urls_with_anchor:
        normalized = url if url.lower().startswith("http") else f"http://{url}"
        if normalized not in seen:
            seen.add(normalized)
            unique_urls.append(normalized)

    return unique_urls, urls_with_anchor


def _extract_attachments(msg: EmailMessage) -> list:
    attachments = []
    if not msg.is_multipart():
        return attachments

    for part in msg.walk():
        disp = str(part.get("Content-Disposition") or "")
        filename = part.get_filename()
        if "attachment" not in disp and not filename:
            continue
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        attachments.append(
            Attachment(
                filename=filename or "(sem_nome)",
                content_type=part.get_content_type(),
                size_bytes=len(payload),
                sha256=hashlib.sha256(payload).hexdigest() if payload else "",
            )
        )
    return attachments


def extract_domain(email_or_url: str) -> str:
    """Extrai o domínio de um endereço de e-mail OU de uma URL."""
    if "@" in email_or_url and "://" not in email_or_url:
        return email_or_url.rsplit("@", 1)[-1].lower().strip(">").strip()
    parsed = urlparse(email_or_url if "://" in email_or_url else f"http://{email_or_url}")
    return (parsed.netloc or parsed.path).split(":")[0].lower()
