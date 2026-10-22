ALTER TABLE guests
ADD COLUMN invite_status TEXT NOT NULL DEFAULT 'not_invited'
CHECK (invite_status IN ('invited', 'not_invited'));

ALTER TABLE photos
ADD COLUMN guest_id TEXT REFERENCES guests(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS photos_guest_id_idx ON photos(guest_id);
