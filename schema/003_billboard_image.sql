-- Adds an optional photo (drone shot / billboard picture) to each listing.
--
-- Stored as a base64 data URL in a TEXT column. The dashboard downscales and
-- re-encodes to JPEG client-side before upload, so rows stay well under D1's
-- ~2MB per-row ceiling. The API never returns this column in list payloads —
-- it exposes a `hasImage` flag instead and serves the bytes from
-- GET /api/billboards/<id>/image so the map feed stays small.
--
-- Purely additive; no table rebuild needed.
--
-- Apply with:
--   wrangler d1 execute billboardiq-db --remote --file=schema/003_billboard_image.sql

ALTER TABLE billboards ADD COLUMN image_data TEXT;
