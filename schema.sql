PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    hostname TEXT,
    app_name TEXT,
    user TEXT,
    src_ip TEXT,
    event_type TEXT,
    raw_log TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    rule_name TEXT,
    severity TEXT,
    mitre_technique TEXT,
    src_ip TEXT,
    user TEXT,
    description TEXT,
    status TEXT DEFAULT 'OPEN'
);
