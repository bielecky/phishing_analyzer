"""
reputation.py
Consultas a fontes públicas de reputação:

  - VirusTotal API v3 (domínios, URLs e IPs) -- requer chave gratuita em
    https://www.virustotal.com/gui/my-apikey
  - WHOIS -- idade de registro do domínio (infraestrutura de phishing
    costuma ser registrada dias ou semanas antes da campanha)
  - AbuseIPDB (opcional) -- reputação dos IPs vistos na cadeia Received

Tudo aqui é isolado em classes com fallback silencioso: se não houver
chave de API configurada, ou a consulta falhar, o restante da análise
continua funcionando normalmente (só aquele indicador fica "não checado").
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import requests

VT_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"


@dataclass
class VTVerdict:
    checked: bool = False
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: Optional[int] = None
    categories: dict = field(default_factory=dict)
    error: str = ""

    @property
    def is_flagged(self) -> bool:
        return self.malicious > 0 or self.suspicious > 0


@dataclass
class WhoisVerdict:
    checked: bool = False
    creation_date: Optional[datetime] = None
    age_days: Optional[int] = None
    registrar: str = ""
    error: str = ""


@dataclass
class AbuseIpVerdict:
    checked: bool = False
    abuse_score: Optional[int] = None
    total_reports: int = 0
    country: str = ""
    error: str = ""


class RateLimiter:
    """Rate limiter simples por 'tokens por minuto', pensado para o tier
    gratuito do VirusTotal (4 requisições/min)."""

    def __init__(self, max_per_minute: int = 4):
        self.min_interval = 60.0 / max_per_minute
        self._last_call = 0.0

    def wait(self):
        elapsed = time.monotonic() - self._last_call
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last_call = time.monotonic()


class VirusTotalClient:
    def __init__(self, api_key: str, requests_per_minute: int = 4, timeout: int = 15):
        self.api_key = api_key
        self.timeout = timeout
        self._limiter = RateLimiter(requests_per_minute)

    def _get(self, path: str) -> dict:
        self._limiter.wait()
        resp = requests.get(
            f"{VT_BASE_URL}{path}",
            headers={"x-apikey": self.api_key, "accept": "application/json"},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def check_domain(self, domain: str) -> VTVerdict:
        v = VTVerdict()
        if not self.api_key:
            v.error = "sem API key configurada"
            return v
        try:
            data = self._get(f"/domains/{domain}")
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            v.checked = True
            v.malicious = stats.get("malicious", 0)
            v.suspicious = stats.get("suspicious", 0)
            v.harmless = stats.get("harmless", 0)
            v.undetected = stats.get("undetected", 0)
            v.reputation = attrs.get("reputation")
            v.categories = attrs.get("categories", {})
        except requests.HTTPError as e:
            v.error = f"HTTP {e.response.status_code if e.response is not None else '?'}"
        except Exception as e:
            v.error = str(e)
        return v

    def check_url(self, url: str) -> VTVerdict:
        v = VTVerdict()
        if not self.api_key:
            v.error = "sem API key configurada"
            return v
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        try:
            data = self._get(f"/urls/{url_id}")
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            v.checked = True
            v.malicious = stats.get("malicious", 0)
            v.suspicious = stats.get("suspicious", 0)
            v.harmless = stats.get("harmless", 0)
            v.undetected = stats.get("undetected", 0)
            v.reputation = attrs.get("reputation")
        except requests.HTTPError as e:
            status = e.response.status_code if e.response is not None else None
            if status == 404:
                v.error = "URL ainda não analisada pelo VirusTotal (não submetida)"
            else:
                v.error = f"HTTP {status}"
        except Exception as e:
            v.error = str(e)
        return v

    def check_ip(self, ip: str) -> VTVerdict:
        v = VTVerdict()
        if not self.api_key:
            v.error = "sem API key configurada"
            return v
        try:
            data = self._get(f"/ip_addresses/{ip}")
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            v.checked = True
            v.malicious = stats.get("malicious", 0)
            v.suspicious = stats.get("suspicious", 0)
            v.harmless = stats.get("harmless", 0)
            v.undetected = stats.get("undetected", 0)
            v.reputation = attrs.get("reputation")
        except requests.HTTPError as e:
            v.error = f"HTTP {e.response.status_code if e.response is not None else '?'}"
        except Exception as e:
            v.error = str(e)
        return v


class WhoisClient:
    def __init__(self, timeout: int = 8):
        # O protocolo WHOIS (TCP/43) não é HTTP, então proxies e firewalls
        # corporativos costumam bloqueá-lo sem responder nada -- a conexão
        # fica pendurada em vez de falhar rápido. Forçamos um timeout de
        # socket explícito para essa chamada não travar o resto da análise.
        self.timeout = timeout

    def lookup(self, domain: str) -> WhoisVerdict:
        import threading

        v = WhoisVerdict()
        try:
            import whois  # python-whois -- import tardio (opcional)
        except ImportError:
            v.error = "biblioteca 'python-whois' não instalada"
            return v

        # O protocolo WHOIS (TCP/43) não é HTTP, então proxies e firewalls
        # corporativos costumam bloqueá-lo sem responder nada (a conexão --
        # ou até a resolução de DNS do servidor WHOIS -- fica pendurada em
        # vez de falhar rápido). O parâmetro `timeout` da própria biblioteca
        # cobre o socket, mas não cobre esse tipo de trava; por isso a
        # consulta roda numa thread daemon separada com um prazo duro: se
        # estourar, desistimos e seguimos a análise sem esse dado, em vez de
        # travar a ferramenta inteira.
        outcome: dict = {}

        def _run():
            try:
                outcome["data"] = whois.whois(domain, timeout=self.timeout)
            except Exception as e:  # noqa: BLE001
                outcome["error"] = e

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        thread.join(timeout=self.timeout + 2)

        if thread.is_alive():
            v.error = (
                f"timeout ao consultar WHOIS de {domain} -- porta TCP/43 "
                f"provavelmente bloqueada pela rede/firewall"
            )
            return v

        if "error" in outcome:
            v.error = str(outcome["error"])
            return v

        try:
            data = outcome.get("data")
            creation = getattr(data, "creation_date", None)
            if isinstance(creation, list):
                creation = creation[0] if creation else None
            if creation:
                if creation.tzinfo is None:
                    creation = creation.replace(tzinfo=timezone.utc)
                v.creation_date = creation
                v.age_days = (datetime.now(timezone.utc) - creation).days
            v.registrar = getattr(data, "registrar", "") or ""
            v.checked = True
        except Exception as e:
            v.error = str(e)
        return v


class AbuseIpDbClient:
    def __init__(self, api_key: str, timeout: int = 15):
        self.api_key = api_key
        self.timeout = timeout

    def check_ip(self, ip: str) -> AbuseIpVerdict:
        v = AbuseIpVerdict()
        if not self.api_key:
            v.error = "sem API key configurada"
            return v
        try:
            resp = requests.get(
                f"{ABUSEIPDB_BASE_URL}/check",
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            v.checked = True
            v.abuse_score = data.get("abuseConfidenceScore")
            v.total_reports = data.get("totalReports", 0)
            v.country = data.get("countryCode", "")
        except Exception as e:
            v.error = str(e)
        return v
