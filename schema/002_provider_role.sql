-- Adds support for advertising-provider accounts.
--
-- Both `users.role` and `billboards.type` are TEXT columns with a CHECK
-- constraint baked into CREATE TABLE, so SQLite can't just widen them with
-- ALTER TABLE — each table is rebuilt (new table with the updated CHECK,
-- data copied across, old table dropped, new one renamed into place).
-- Existing billboards.type='digital' rows become 'digital_display';
-- 'static' rows become 'hoarding' (there is no pre-existing data mapping
-- to the new 'banner' type).
--
-- Apply with:
--   wrangler d1 execute billboardiq-db --remote --file=schema/002_provider_role.sql

PRAGMA foreign_keys=OFF;

CREATE TABLE users_new (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','provider','admin','superuser')),
  company_name TEXT,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  mfa_enabled INTEGER NOT NULL DEFAULT 0,
  mfa_secret TEXT,
  mfa_pending_secret TEXT,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER,
  created_at INTEGER NOT NULL,
  last_login INTEGER,
  verified INTEGER NOT NULL DEFAULT 0
);

INSERT INTO users_new (id,email,name,role,company_name,password_hash,password_salt,mfa_enabled,mfa_secret,mfa_pending_secret,failed_attempts,locked_until,created_at,last_login,verified)
SELECT id,email,name,role,NULL,password_hash,password_salt,mfa_enabled,mfa_secret,mfa_pending_secret,failed_attempts,locked_until,created_at,last_login,verified
FROM users;

DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

CREATE TABLE billboards_new (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  area TEXT NOT NULL,
  description TEXT,
  lat REAL NOT NULL,
  lng REAL NOT NULL,
  size TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('hoarding','banner','digital_display')),
  category TEXT NOT NULL CHECK (category IN ('highway','arterial','local')),
  illuminated INTEGER NOT NULL DEFAULT 0,
  price INTEGER NOT NULL,
  traffic INTEGER NOT NULL,
  peak_hours TEXT,
  audience_male INTEGER DEFAULT 50,
  audience_female INTEGER DEFAULT 50,
  audience_age TEXT DEFAULT '25-44',
  audience_income TEXT DEFAULT 'Mid',
  availability TEXT NOT NULL DEFAULT 'available' CHECK (availability IN ('available','pending','booked')),
  approval_state TEXT NOT NULL DEFAULT 'draft' CHECK (approval_state IN ('draft','pending','approved','rejected')),
  rejection_note TEXT,
  reviewed_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  reviewed_at INTEGER,
  owner_verified INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  data_sources TEXT
);

INSERT INTO billboards_new (id,owner_id,title,area,description,lat,lng,size,type,category,illuminated,price,traffic,peak_hours,audience_male,audience_female,audience_age,audience_income,availability,approval_state,rejection_note,reviewed_by,reviewed_at,owner_verified,created_at,updated_at,data_sources)
SELECT id,owner_id,title,area,description,lat,lng,size,
  CASE type WHEN 'digital' THEN 'digital_display' WHEN 'static' THEN 'hoarding' ELSE type END,
  category,illuminated,price,traffic,peak_hours,audience_male,audience_female,audience_age,audience_income,availability,approval_state,rejection_note,reviewed_by,reviewed_at,owner_verified,created_at,updated_at,data_sources
FROM billboards;

DROP TABLE billboards;
ALTER TABLE billboards_new RENAME TO billboards;

CREATE INDEX idx_billboards_owner ON billboards(owner_id);
CREATE INDEX idx_billboards_state ON billboards(approval_state);

PRAGMA foreign_keys=ON;
