import sqlite3

DB_PATH = "nids.db"


def get_connection(db_path=DB_PATH):
    """Ouvre une connexion à la base SQLite."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # permet d'accéder aux colonnes par leur nom
    conn.execute("PRAGMA foreign_keys = ON")  # active la clé étrangère alerts -> hosts
    return conn


def create_tables(db_path=DB_PATH):
    """Crée les 3 tables du schéma (si elles n'existent pas déjà)."""
    conn = get_connection(db_path)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS hosts (
            ip          TEXT PRIMARY KEY,
            first_seen  TEXT NOT NULL,
            last_seen   TEXT NOT NULL,
            is_active   INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip            TEXT NOT NULL,
            dst_ip            TEXT NOT NULL,
            timestamp         TEXT NOT NULL,
            anomaly_type      TEXT NOT NULL,
            score             REAL NOT NULL,
            status            TEXT NOT NULL DEFAULT 'new',
            reputation_score  INTEGER,
            country           TEXT,
            FOREIGN KEY (src_ip) REFERENCES hosts(ip)
        );

        CREATE TABLE IF NOT EXISTS traffic_stats (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     TEXT NOT NULL,
            packet_count  INTEGER NOT NULL,
            byte_count    INTEGER NOT NULL
        );
    """)
    conn.commit()
    conn.close()


if __name__ == "__main__":
    create_tables()
    print(f"Tables créées dans {DB_PATH}")