-- Adds a booking window to billboards so "expiry and renewal" has a real
-- signal to work with, instead of just the availability status.
--
-- Set whenever a provider marks a listing "booked" (dashboard.html shows the
-- two date fields only in that case). Renewal is just editing an existing
-- booked listing and pushing booking_end further out — no separate
-- contracts/bookings table.
--
-- Apply with:
--   wrangler d1 execute billboardiq-db --remote --file=schema/005_booking_dates.sql

ALTER TABLE billboards ADD COLUMN booking_start INTEGER;
ALTER TABLE billboards ADD COLUMN booking_end INTEGER;
