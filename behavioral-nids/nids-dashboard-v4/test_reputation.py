import json

import pytest

import reputation
from reputation import ReputationClient, is_checkable, is_local, pick_remote_ip


def ok_body(score=87, country="FR"):
    return json.dumps({"data": {"abuseConfidenceScore": score, "countryCode": country}})


class FakeFetch:
    def __init__(self, status=200, body=None, headers=None, raises=None):
        self.status, self.body = status, body if body is not None else ok_body()
        self.headers, self.raises = headers or {}, raises
        self.calls = []

    def __call__(self, url, headers, timeout):
        self.calls.append((url, headers))
        if self.raises:
            raise self.raises
        return self.status, self.body, self.headers


def make(fetch, **kw):
    kw.setdefault("local_ips", {"192.168.1.20"})
    return ReputationClient(api_key="secret", fetch=fetch, **kw)


@pytest.mark.parametrize("ip,expected", [
    ("8.8.8.8", True), ("2a01:cb19:65c:7c00::1", True),
    ("192.168.1.1", False), ("127.0.0.1", False), ("::1", False),
    ("fe80::1", False), ("fd00::1", False), ("224.0.0.251", False),
    ("ff02::fb", False), ("255.255.255.255", False), ("pas-une-ip", False),
])
def test_is_checkable(ip, expected):
    assert is_checkable(ip) == expected


def test_pick_remote_ip():
    assert pick_remote_ip("192.168.1.20", "8.8.8.8", {"192.168.1.20"}) == "8.8.8.8"
    assert pick_remote_ip("8.8.4.4", "192.168.1.20", {"192.168.1.20"}) == "8.8.4.4"
    assert pick_remote_ip("192.168.1.20", "224.0.0.251", {"192.168.1.20"}) is None


def test_check_ok_et_requete_correcte():
    f = FakeFetch()
    assert make(f).check("8.8.8.8") == {"reputation_score": 87, "country": "FR"}
    url, headers = f.calls[0]
    assert url.startswith(reputation.API_URL) and "ipAddress=8.8.8.8" in url
    assert headers["Key"] == "secret" and headers["Accept"] == "application/json"


def test_ipv6_est_encodee():
    f = FakeFetch()
    make(f).check("2a01:cb19:65c:7c00::1")
    assert "ipAddress=2a01%3Acb19%3A65c%3A7c00%3A%3A1" in f.calls[0][0]


def test_sans_cle_desactive():
    f = FakeFetch()
    c = ReputationClient(api_key="", fetch=f, local_ips=set())
    assert not c.enabled and c.check("8.8.8.8") is None and f.calls == []


def test_ip_privee_jamais_envoyee():
    f = FakeFetch()
    c = make(f)
    assert c.check("192.168.1.1") is None and c.check("192.168.1.20") is None
    assert f.calls == []


def test_cache():
    f = FakeFetch()
    c = make(f)
    c.check("8.8.8.8"); c.check("8.8.8.8")
    assert len(f.calls) == 1


def test_cache_expire():
    t = [1000.0]
    f = FakeFetch()
    c = make(f, ttl=100, clock=lambda: t[0])
    c.check("8.8.8.8"); t[0] += 101; c.check("8.8.8.8")
    assert len(f.calls) == 2


def test_budget_quotidien():
    f = FakeFetch()
    c = make(f, daily_budget=2)
    for ip in ("8.8.8.8", "8.8.4.4", "1.1.1.1"):
        c.check(ip)
    assert len(f.calls) == 2


def test_429_bloque_puis_reprend():
    t = [1000.0]
    f = FakeFetch(status=429, headers={"Retry-After": "60"})
    c = make(f, clock=lambda: t[0])
    assert c.check("8.8.8.8") is None
    c.check("1.1.1.1")
    assert len(f.calls) == 1          # bloqué : aucun nouvel appel
    t[0] += 61
    c.check("1.1.1.1")
    assert len(f.calls) == 2


@pytest.mark.parametrize("fetch", [
    FakeFetch(status=401, body='{"errors":[{"detail":"bad key"}]}'),
    FakeFetch(status=422, body="{}"),
    FakeFetch(body="pas du json"),
    FakeFetch(body='{"data": {}}'),
    FakeFetch(raises=TimeoutError("lent")),
    FakeFetch(raises=OSError("réseau coupé")),
])
def test_erreurs_ne_plantent_jamais(fetch):
    assert make(fetch).check("8.8.8.8") is None


def test_enrich_choisit_l_ip_distante():
    f = FakeFetch()
    c = make(f)
    assert c.enrich("192.168.1.20", "8.8.8.8")["reputation_score"] == 87
    assert "ipAddress=8.8.8.8" in f.calls[0][0]
    assert c.enrich("192.168.1.20", "ff02::fb") is None


def test_detect_local_ips_lit_la_variable(monkeypatch):
    monkeypatch.setenv("NIDS_LOCAL_IPS", "2a01:aaaa::1, 10.0.0.5")
    ips = reputation.detect_local_ips()
    assert {"2a01:aaaa::1", "10.0.0.5"} <= ips


MON_V6 = "2a01:cb19:65c:7c00:5d3f:63a7:b582:a652"
AUTRE_V6_DU_MEME_RESEAU = "2a01:cb19:65c:7c00:1111:2222:3333:4444"


def test_is_local_meme_reseau_ipv6():
    assert is_local(AUTRE_V6_DU_MEME_RESEAU, {MON_V6})
    assert not is_local("2a01:cb19:65c:7c01::1", {MON_V6})   # autre reseau /64
    assert not is_local("2606:4700::1111", {MON_V6})


def test_ipv6_du_mac_n_est_jamais_verifiee():
    f = FakeFetch()
    c = make(f, local_ips={MON_V6})
    assert c.check(AUTRE_V6_DU_MEME_RESEAU) is None
    assert c.enrich(AUTRE_V6_DU_MEME_RESEAU, "8.8.8.8")["reputation_score"] == 87
    assert "ipAddress=8.8.8.8" in f.calls[0][0] and len(f.calls) == 1