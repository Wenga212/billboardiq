-- Backs the admin console's "Simulate test data" toggle (Console → Test
-- Data, superuser only): companies.is_test_data=1 marks a company as
-- simulated demo data (see functions/api/[[route]].js seedTestData/
-- purgeTestData). Billboards/users under such a company are excluded from
-- the public marketplace, the signup company picker, and the real
-- traffic-engine Worker's cron — they only ever show up in the admin
-- console, for exercising it without touching real listings or spending
-- real Google Routes API budget on fake locations.
--
-- Apply with:
--   wrangler d1 execute billboardiq-db --remote --file=schema/013_test_data_flag.sql

ALTER TABLE companies ADD COLUMN is_test_data INTEGER NOT NULL DEFAULT 0;
CREATE INDEX idx_companies_test_data ON companies(is_test_data);
