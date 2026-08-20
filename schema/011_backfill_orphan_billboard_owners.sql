-- Follow-up to schema/008: that migration's backfill only covered
-- role='provider' (the only role that had company_name history). A few
-- existing billboards turned out to be owned directly by an
-- admin/superuser account with no company_id, which would leave them
-- orphaned under the new company-scoped model (invisible to
-- billboards/mine, unassignable from the map's Edit action for anyone but
-- an admin going through the admin console). This generalizes the same
-- backfill to any billboard owner, regardless of role, using their email
-- (globally unique) to derive a fallback company name.
--
-- Apply with:
--   wrangler d1 execute billboardiq-db --remote --file=schema/011_backfill_orphan_billboard_owners.sql

UPDATE users
SET company_name = COALESCE(NULLIF(TRIM(name), ''), email) || ' — Co.'
WHERE company_id IS NULL
  AND id IN (SELECT DISTINCT owner_id FROM billboards WHERE company_id IS NULL);

INSERT INTO companies (id, name, type, created_at)
SELECT 'CO-' || upper(hex(randomblob(4))), company_name, 'provider', strftime('%s','now') * 1000
FROM (SELECT DISTINCT company_name FROM users WHERE company_id IS NULL AND company_name IS NOT NULL);

UPDATE users
SET company_id = (SELECT id FROM companies WHERE companies.name = users.company_name)
WHERE company_id IS NULL AND company_name IS NOT NULL;

UPDATE billboards
SET company_id = (SELECT company_id FROM users WHERE users.id = billboards.owner_id)
WHERE company_id IS NULL;
