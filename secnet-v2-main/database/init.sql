-- Initialize the alerts table
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    alert_message TEXT,
    severity INTEGER,
    protocol TEXT,
    action_taken TEXT,
    raw_data TEXT
);

-- Initialize the blocked_ips table
CREATE TABLE IF NOT EXISTS blocked_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE,
    timestamp TEXT,
    reason TEXT
);
