CREATE TABLE IF NOT EXISTS guests (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 160),
    invite_code TEXT NOT NULL UNIQUE CHECK (length(invite_code) = 8),
    created_at TEXT NOT NULL,
    source_key TEXT UNIQUE
);

CREATE TABLE IF NOT EXISTS wishes (
    guest_id TEXT PRIMARY KEY REFERENCES guests(id) ON DELETE CASCADE,
    message TEXT NOT NULL CHECK (length(trim(message)) BETWEEN 1 AND 2000),
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS photos (
    photo_id TEXT PRIMARY KEY,
    captured_at TEXT NOT NULL,
    style TEXT NOT NULL,
    orientation TEXT NOT NULL CHECK (orientation IN ('portrait', 'landscape')),
    telegram_status TEXT NOT NULL CHECK (telegram_status IN ('pending', 'sent', 'failed')),
    telegram_message_id INTEGER
);

CREATE TABLE IF NOT EXISTS api_rate_limits (
    key_hash TEXT PRIMARY KEY,
    window_started INTEGER NOT NULL,
    request_count INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS wishes_updated_at_idx ON wishes(updated_at DESC);
CREATE INDEX IF NOT EXISTS photos_captured_at_idx ON photos(captured_at DESC);
