-- Agent "customer" tenants (e.g. an advertiser like Coca-Cola) that an
-- advertising agent tracks bookings and an informal marketing budget for.
-- Scoped to the agent's own company (companies.id) — every member of that
-- company shares the same customer list, same as billboards became
-- company-shared in schema/008.
--
-- billboards.customer_id records which customer currently occupies a
-- *booked* billboard — same "single current booking, no history table"
-- simplicity as booking_start/booking_end (schema/005). Budget tracking is
-- informational only: nothing here blocks a booking, it's purely for the
-- agent dashboard to show spend vs. remaining budget.
--
-- Apply with:
--   wrangler d1 execute billboardiq-db --remote --file=schema/009_customers.sql

CREATE TABLE customers (
  id TEXT PRIMARY KEY,
  company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  budget INTEGER,
  notes TEXT,
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX idx_customers_company ON customers(company_id);

ALTER TABLE billboards ADD COLUMN customer_id TEXT REFERENCES customers(id);
CREATE INDEX idx_billboards_customer ON billboards(customer_id);
