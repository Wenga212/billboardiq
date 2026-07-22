-- Per-provider catalog of billboard formats (sizes/screens they offer).
--
-- The Add Billboard "Size" field used to be free text. It's now a dropdown
-- populated from the signed-in provider's own catalog here, so a provider
-- only ever sees the formats they've defined for themselves. Hoarding/banner
-- rows use `size`; digital_display rows use building_name/resolution/
-- ad_duration instead.
--
-- billboards.format_id points back at the catalog entry a listing was
-- created from, but the relevant fields are also denormalized onto the
-- billboard row itself (size/building_name/resolution/ad_duration) so a
-- listing keeps its data even if the catalog entry is later deleted
-- (ON DELETE SET NULL, not cascade).
--
-- Apply with:
--   wrangler d1 execute billboardiq-db --remote --file=schema/004_billboard_formats.sql

CREATE TABLE billboard_formats (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type TEXT NOT NULL CHECK (type IN ('hoarding','banner','digital_display')),
  size TEXT,
  building_name TEXT,
  resolution TEXT,
  ad_duration TEXT,
  created_at INTEGER NOT NULL
);

CREATE INDEX idx_billboard_formats_owner ON billboard_formats(owner_id);

ALTER TABLE billboards ADD COLUMN format_id TEXT REFERENCES billboard_formats(id) ON DELETE SET NULL;
ALTER TABLE billboards ADD COLUMN building_name TEXT;
ALTER TABLE billboards ADD COLUMN resolution TEXT;
ALTER TABLE billboards ADD COLUMN ad_duration TEXT;
