"""Enrichissement des alertes avec la réputation d'une IP (AbuseIPDB).

- Clé lue dans la variable d'environnement ABUSEIPDB_API_KEY (jamais dans le code).
- Sans clé, le module est désactivé : enrich() renvoie None, rien ne plante.
- Seules les IP publiques sont envoyées (pas les IP locales, multicast, etc.).
- Cache mémoire 24 h + budget quotidien (le plan gratuit permet 1000 requêtes/jour).
- Ne lève jamais d'exception : en cas de problème, on renvoie None.
"""
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

API_URL = "https://api.abuseipdb.com/api/v2/check"
ENV_KEY = "ABUSEIPDB_API_KEY"
ENV_LOCAL_IPS = "NIDS_LOCAL_IPS"


def detect_local_ips():
    """IP de ce Mac (pour ne jamais les envoyer à AbuseIPDB).

    Ajoute celles de la variable NIDS_LOCAL_IPS (séparées par des virgules),
    utile pour l'IPv6 de la machine.
    """
    ips = set()
    for target, family in (("8.8.8.8", socket.AF_INET), ("2001:4860:4860::8888", socket.AF_INET6)):
        try:
            s = socket.socket(family, socket.SOCK_DGRAM)
            s.connect((target, 80))  # UDP : n'envoie aucun paquet
            ips.add(s.getsockname()[0].split("%")[0])
            s.close()
        except OSError:
            pass
    try:  # toutes les adresses de la machine (IPv4 + IPv6), via ifconfig
        out = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=3).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("inet", "inet6"):
                ips.add(parts[1].split("%")[0])
    except (OSError, subprocess.SubprocessError):
        pass
    for item in os.environ.get(ENV_LOCAL_IPS, "").split(","):
        if item.strip():
            ips.add(item.strip())
    return ips


def is_checkable(ip):
    """True si l'IP est publique et valide (donc utile à vérifier)."""
    try:
        addr = ipaddress.ip_address(str(ip).split("%")[0])
    except ValueError:
        return False
    # is_global est aussi True pour le multicast : on l'exclut à part
    return addr.is_global and not addr.is_multicast


def is_local(ip, local_ips):
    """True si l'IP est celle de cette machine, ou une autre adresse IPv6 de son réseau /64.

    (Le Mac change régulièrement d'adresse IPv6 « temporaire » : on compare donc le réseau.)
    """
    ip = str(ip).split("%")[0]
    if ip in local_ips:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version != 6:
        return False
    for other in local_ips:
        try:
            o = ipaddress.ip_address(other)
        except ValueError:
            continue
        if o.version == 6 and not o.is_link_local and addr in ipaddress.ip_network(f"{o}/64", strict=False):
            return True
    return False


def pick_remote_ip(src_ip, dst_ip, local_ips=()):
    """Choisit l'IP « distante » (celle qui n'est pas ce Mac) à vérifier."""
    local = set(local_ips)
    for ip in (src_ip, dst_ip):
        if ip and not is_local(ip, local) and is_checkable(ip):
            return ip
    return None


def _default_fetch(url, headers, timeout):
    """Appel HTTP réel. Renvoie (status, corps_texte, en-têtes)."""
    req = urllib.request.Request(url, headers=headers)
    context = None
    try:  # certificats de certifi (utile avec le Python de python.org sur Mac)
        import certifi
        context = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        pass
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            return resp.status, resp.read().decode("utf-8", "replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers or {})


class ReputationClient:
    def __init__(self, api_key=None, fetch=None, ttl=86400, daily_budget=900,
                 timeout=3, local_ips=None, clock=time.time, max_age_days=90):
        self.api_key = api_key if api_key is not None else os.environ.get(ENV_KEY, "")
        self.fetch = fetch or _default_fetch
        self.ttl = ttl
        self.daily_budget = daily_budget
        self.timeout = timeout
        self.max_age_days = max_age_days
        self.clock = clock
        self.local_ips = set(local_ips) if local_ips is not None else detect_local_ips()
        self._cache = {}          # ip -> (heure, résultat ou None)
        self._day = None
        self._used = 0
        self._blocked_until = 0   # après un 429

    @property
    def enabled(self):
        return bool(self.api_key)

    def _budget_ok(self, now):
        day = int(now // 86400)
        if day != self._day:
            self._day, self._used = day, 0
        return self._used < self.daily_budget and now >= self._blocked_until

    def check(self, ip):
        """{"reputation_score": int, "country": str|None} ou None."""
        if not self.enabled or not is_checkable(ip) or is_local(ip, self.local_ips):
            return None
        now = self.clock()
        hit = self._cache.get(ip)
        if hit and now - hit[0] < self.ttl:
            return hit[1]
        if not self._budget_ok(now):
            return None

        url = API_URL + "?" + urllib.parse.urlencode(
            {"ipAddress": ip, "maxAgeInDays": self.max_age_days})
        headers = {"Key": self.api_key, "Accept": "application/json"}
        self._used += 1
        try:
            status, body, resp_headers = self.fetch(url, headers, self.timeout)
        except Exception:  # réseau coupé, timeout, DNS...
            return None

        if status == 429:
            try:
                wait = int({k.lower(): v for k, v in resp_headers.items()}.get("retry-after", 3600))
            except (TypeError, ValueError):
                wait = 3600
            self._blocked_until = now + wait
            return None
        if status != 200:  # 401 clé invalide, 422 paramètre invalide...
            return None
        try:
            data = json.loads(body)["data"]
            result = {
                "reputation_score": int(data["abuseConfidenceScore"]),
                "country": data.get("countryCode"),
            }
        except (ValueError, KeyError, TypeError):
            return None

        self._cache[ip] = (now, result)
        return result

    def enrich(self, src_ip, dst_ip):
        """Réputation de l'IP distante d'une alerte, ou None."""
        ip = pick_remote_ip(src_ip, dst_ip, self.local_ips)
        return self.check(ip) if ip else None