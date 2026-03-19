-- ============================================================
--  Calendar Subscribe System — D1 Schema
--  Safe to run: uses CREATE TABLE IF NOT EXISTS
--  Will NEVER touch or modify any existing tables.
-- ============================================================

CREATE TABLE IF NOT EXISTS calendars (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT    NOT NULL,
  slug        TEXT    NOT NULL UNIQUE,   -- used in .ics URL: /api/calendars/:slug/ics
  description TEXT,
  color       TEXT    DEFAULT '#6ee7b7', -- hex color shown on subscribe page
  status      TEXT    DEFAULT 'active',  -- 'active' | 'draft'
  created_at  TEXT    DEFAULT (datetime('now')),
  updated_at  TEXT    DEFAULT (datetime('now'))
);

-- Optional: index for fast slug lookups
CREATE INDEX IF NOT EXISTS idx_calendars_slug   ON calendars (slug);
CREATE INDEX IF NOT EXISTS idx_calendars_status ON calendars (status);

-- ============================================================
--  Seed some example calendars (safe — INSERT OR IGNORE)
--  Remove or edit these as needed.
-- ============================================================

INSERT OR IGNORE INTO calendars (name, slug, description, color, status) VALUES
  ('Example Calendar',   'example',   'A sample calendar to get you started.',  '#6ee7b7', 'draft'),
  ('Community Events',   'community', 'Local events open to everyone.',          '#818cf8', 'active');
