"""Capture reseau reelle : lit la sortie de `tcpdump`, reconstitue des FLUX, les note, ecrit dans la base.

Securite : seul tcpdump tourne en administrateur ; ce script tourne avec TES droits (donc la
base nids.db t'appartient et le texte venant du reseau n'a jamais de privileges).
On ne lit que des METADONNEES (adresses, ports, tailles). tcpdump est lance avec -s 96 : il ne
capture meme pas le contenu des paquets.

Utilisation (remplace en0 par ton interface, voir README) :

  1) Apprendre ton trafic normal (10 a 15 min d'usage habituel) :
     sudo tcpdump -i en0 -l -n -tt -s 96 'ip or ip6' | python engine/capture.py --learn engine/learned_flows.jsonl
     python engine/train.py --from engine/learned_flows.jsonl

  2) Detecter en direct :
     sudo tcpdump -i en0 -l -n -tt -s 96 'ip or ip6' | python engine/capture.py --live
"""
import argparse
import collections
import json
import os
import re
import select
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

IDLE_TIMEOUT = 10.0      # un flux sans paquet depuis 10 s est termine
CLOSED_GRACE = 2.0       # apres FIN/RST on attend 2 s les derniers paquets
ACTIVE_TIMEOUT = 60.0    # un tres long flux est decoupe toutes les 60 s
WINDOW = 60.0            # fenetre des indicateurs par source (conn_rate, distinct_ports)
MAX_FLOWS = 20000        # garde-fou memoire (scan massif / attaque sur le moniteur lui-meme)

# Ligne tcpdump : "<epoch> IP|IP6 <src> > <dst>: <reste>". Tout ce qui ne colle pas est ignore.
LINE = re.compile(r"^(\d{9,11}\.\d+) IP6? (\S+) > (\S+?): (.*)$")
LENGTH = re.compile(r"length (\d+)\s*$")
FLAGS = re.compile(r"Flags \[([A-Za-z.]*)\]")
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _split_port(addr):
    """'192.168.1.5.52341' -> ('192.168.1.5', 52341) ; '2a01::1.443' -> ('2a01::1', 443)."""
    ip, _, port = addr.rpartition(".")
    if not ip or not port.isdigit() or not 0 <= int(port) <= 65535:
        return None
    return ip, int(port)


def parse_line(line):
    """Une ligne tcpdump -> dict paquet, ou None si non pris en charge."""
    m = LINE.match(line.strip())
    if not m:
        return None
    ts, src, dst, rest = float(m.group(1)), m.group(2), m.group(3), m.group(4)
    ln = LENGTH.search(rest)
    size = int(ln.group(1)) if ln else 0

    if rest.startswith("ICMP"):
        proto, sport, dport = "ICMP", None, None
        if not _valid_ip(src) or not _valid_ip(dst):
            return None
        sip, dip = src, dst
    else:
        if rest.startswith("UDP"):
            proto = "UDP"
        elif rest.startswith("Flags ["):
            proto = "TCP"
        else:
            return None
        a, b = _split_port(src), _split_port(dst)
        if not a or not b:
            return None
        (sip, sport), (dip, dport) = a, b
    fl = FLAGS.search(rest)
    return {"ts": ts, "src": sip, "dst": dip, "sport": sport, "dport": dport, "proto": proto,
            "size": size, "flags": fl.group(1) if fl else ""}


def _valid_ip(s):
    return bool(IPV4.match(s)) or (":" in s and re.fullmatch(r"[0-9a-fA-F:]+", s) is not None)


def is_noise(dst):
    """Multicast / broadcast : bruit (mDNS, SSDP...), sans interet pour detecter un comportement."""
    return dst.startswith(("224.", "239.", "255.", "ff0", "ff1", "ff2")) or dst.endswith(".255")


class FlowTable:
    """Regroupe les paquets en flux et calcule les indicateurs comportementaux par source."""

    def __init__(self):
        self.flows = {}
        self.recent = collections.defaultdict(collections.deque)  # src -> deque[(ts, dport)]

    @staticmethod
    def _key(p):
        """Meme cle pour les deux sens d'une conversation."""
        ends = sorted([(p["src"], p["sport"] or 0), (p["dst"], p["dport"] or 0)])
        return (p["proto"],) + tuple(ends)

    def add(self, p):
        if is_noise(p["dst"]):
            return
        k = self._key(p)
        f = self.flows.get(k)
        if f is None:
            if len(self.flows) >= MAX_FLOWS:
                return
            f = self._new(p)
            self.flows[k] = f
        out = p["src"] == f["src_ip"]
        f["last"] = p["ts"]
        f["packets"] += 1
        if out:
            f["src_bytes"] += p["size"]
        else:
            f["dst_bytes"] += p["size"]
            f["replied"] = True
        fl = p["flags"]
        if "R" in fl:
            f["reset"] = True
            f["closed_at"] = p["ts"]
        if "F" in fl and "closed_at" not in f:
            f["closed_at"] = p["ts"]

    def _new(self, p):
        q = self.recent[p["src"]]
        while q and p["ts"] - q[0][0] > WINDOW:
            q.popleft()
        q.append((p["ts"], p["dport"]))
        return {
            "src_ip": p["src"], "dst_ip": p["dst"], "dst_port": p["dport"], "proto": p["proto"],
            "start": p["ts"], "last": p["ts"], "packets": 0, "src_bytes": 0, "dst_bytes": 0,
            "replied": False, "reset": False,
            "conn_rate": len(q), "distinct_ports": len({d for _, d in q}),
        }

    def expire(self, now, flush_all=False):
        """Renvoie les flux termines (dicts de caracteristiques) et les retire de la table."""
        done = []
        for k in list(self.flows):
            f = self.flows[k]
            idle = now - f["last"]
            closed = "closed_at" in f and now - f["closed_at"] > CLOSED_GRACE
            if flush_all or idle > IDLE_TIMEOUT or closed or f["last"] - f["start"] > ACTIVE_TIMEOUT:
                done.append(self._finish(self.flows.pop(k)))
        return done

    @staticmethod
    def _finish(f):
        failed = f["reset"] or (f["proto"] == "TCP" and not f["replied"])
        return {
            "src_ip": f["src_ip"], "dst_ip": f["dst_ip"], "dst_port": f["dst_port"], "proto": f["proto"],
            "duration": max(0.0, f["last"] - f["start"]), "src_bytes": float(f["src_bytes"]),
            "dst_bytes": float(f["dst_bytes"]), "packets": float(f["packets"]),
            "failed": int(failed), "conn_rate": float(f["conn_rate"]),
            "distinct_ports": float(f["distinct_ports"]),
        }


def read_lines(fd=0):
    """Generateur de lignes depuis un tube ; donne None toutes les secondes s'il n'y a rien (pour expirer)."""
    buf = b""
    while True:
        ready, _, _ = select.select([fd], [], [], 1.0)
        if not ready:
            yield None
            continue
        chunk = os.read(fd, 65536)
        if not chunk:
            if buf:
                yield buf.decode("utf-8", "replace")
            return
        buf += chunk
        *lines, buf = buf.split(b"\n")
        for ln in lines:
            yield ln.decode("utf-8", "replace")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--learn", metavar="FICHIER", help="enregistre les flux (pour entrainer ton modele)")
    g.add_argument("--live", action="store_true", help="note les flux et alimente le dashboard")
    ap.add_argument("--model", default=None, help="modele a utiliser (defaut : engine/model_real.pkl)")
    args = ap.parse_args()

    det = None
    if args.live:
        import db
        from engine import run_detection
        model_path = args.model or os.path.join(os.path.dirname(os.path.abspath(__file__)), "model_real.pkl")
        if not os.path.exists(model_path):
            sys.exit("Pas de modele appris sur ton reseau. Lance d'abord --learn puis train.py --from ...")
        det = run_detection.load_model(model_path)
        db.init_db()
        with db.connect() as conn:
            db.set_meta(conn, "demo", "0")  # vrai trafic : le bandeau demo disparait

    table = FlowTable()
    last_ts, last_wall, n_flows = None, time.time(), 0
    out = open(args.learn, "a", encoding="utf-8") if args.learn else None
    print("Capture en cours... Ctrl+C pour arreter.", file=sys.stderr)

    def handle(done, now_ts):
        nonlocal n_flows
        if not done:
            return
        n_flows += len(done)
        if out:
            for f in done:
                out.write(json.dumps(f) + "\n")
            out.flush()
        else:
            when = datetime.fromtimestamp(now_ts, timezone.utc).replace(microsecond=0)
            with db.connect() as conn:
                n = run_detection.process(conn, det, done, when)
            if n:
                print(when.strftime("%H:%M:%S"), "->", n, "alerte(s)", file=sys.stderr)

    try:
        for line in read_lines():
            if line is not None:
                p = parse_line(line)
                if p:
                    table.add(p)
                    last_ts, last_wall = p["ts"], time.time()
            if last_ts is not None:
                now_ts = last_ts + (time.time() - last_wall)
                handle(table.expire(now_ts), now_ts)
        if last_ts is not None:
            handle(table.expire(last_ts, flush_all=True), last_ts)
    except KeyboardInterrupt:
        pass
    finally:
        if out:
            out.close()
            print(f"\n{n_flows} flux enregistres dans {args.learn}", file=sys.stderr)


if __name__ == "__main__":
    main()
