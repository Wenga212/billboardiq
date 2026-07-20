-- Adds support for advertising-provider accounts.
--
-- BEFORE running this, confirm neither `users.role` nor `billboards.type` has
-- a CHECK constraint that would reject the new values this feature adds
-- ('provider' for role; 'hoarding' / 'banner' / 'digital_display' for type):
--   wrangler d1 execute <DB_NAME> --remote --command \
--     "SELECT sql FROM sqlite_master WHERE type='table' AND name IN ('users','billboards')"
-- If either has a CHECK(...) listing the old values, that table needs to be
-- rebuilt (SQLite can't ALTER a CHECK constraint in place) before the new
-- role/type values will insert successfully.
--
-- Then apply this migration:
--   wrangler d1 execute <DB_NAME> --remote --file=schema/002_provider_role.sql

ALTER TABLE users ADD COLUMN company_name TEXT;
