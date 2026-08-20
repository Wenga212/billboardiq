-- Adds a real `companies` entity and a new `agent` role (advertising
-- agencies who book existing inventory on behalf of their own clients,
-- as distinct from `provider` — companies that own the physical
-- billboards). Backfills company_id for every existing provider (and
-- their billboards) from the free-text company_name that already
-- existed, so no existing account loses access or gets signed out.
--
-- users.role is a TEXT column with a CHECK constraint baked into
-- CREATE TABLE, so SQLite can't widen it with ALTER TABLE — the table
-- is rebuilt (new table with the updated CHECK + company_id column,
-- data copied across, old table dropped, new one renamed into place).
-- Same pattern as schema/002_provider_role.sql.
--
-- Apply with:
--   wrangler d1 execute billboardiq-db --remote --file=schema/008_companies_agent_role.sql

PRAGMA foreign_keys=OFF;

CREATE TABLE companies (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL DEFAULT 'provider' CHECK (type IN ('provider','agency')),
  created_at INTEGER NOT NULL
);

CREATE TABLE users_new (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','provider','agent','admin','superuser')),
  company_name TEXT,
  company_id TEXT REFERENCES companies(id) ON DELETE SET NULL,
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

INSERT INTO users_new (id,email,name,role,company_name,company_id,password_hash,password_salt,mfa_enabled,mfa_secret,mfa_pending_secret,failed_attempts,locked_until,created_at,last_login,verified)
SELECT id,email,name,role,company_name,NULL,password_hash,password_salt,mfa_enabled,mfa_secret,mfa_pending_secret,failed_attempts,locked_until,created_at,last_login,verified
FROM users;

DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

CREATE INDEX idx_users_company ON users(company_id);

ALTER TABLE billboards ADD COLUMN company_id TEXT REFERENCES companies(id);
CREATE INDEX idx_billboards_company ON billboards(company_id);

PRAGMA foreign_keys=ON;

-- ---------------- backfill ----------------

-- Edge case safety net: register() has always required a companyName for
-- provider signups, so this should affect zero rows in practice, but give
-- any provider missing one a fallback name so they still end up grouped
-- into a real company below instead of staying company-less.
UPDATE users
SET company_name = COALESCE(NULLIF(TRIM(name), ''), email) || ' — Co.'
WHERE role = 'provider' AND (company_name IS NULL OR TRIM(company_name) = '');

-- One company per distinct existing provider company_name.
INSERT INTO companies (id, name, type, created_at)
SELECT 'CO-' || upper(hex(randomblob(4))), company_name, 'provider', strftime('%s','now') * 1000
FROM (SELECT DISTINCT company_name FROM users WHERE role = 'provider' AND company_name IS NOT NULL AND TRIM(company_name) != '');

UPDATE users
SET company_id = (SELECT id FROM companies WHERE companies.name = users.company_name)
WHERE role = 'provider' AND company_name IS NOT NULL AND TRIM(company_name) != '';

-- Every existing billboard inherits its owner's freshly-backfilled company.
UPDATE billboards
SET company_id = (SELECT company_id FROM users WHERE users.id = billboards.owner_id)
WHERE company_id IS NULL;
