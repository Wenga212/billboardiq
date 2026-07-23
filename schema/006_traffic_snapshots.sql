-- Historical traffic data collected by the standalone analytics Worker
-- (worker/) — a Cron Trigger periodically screenshots Google Maps' traffic
-- layer at each approved billboard's coordinates, has Claude's vision read
-- the congestion colors, stores only the extracted numbers here, and
-- discards the screenshot. Never persists an image anywhere.
--
-- billboards.facing is the compass direction the board points (set in the
-- Add Billboard form); ai_insights/ai_insights_updated_at cache a
-- periodically-regenerated plain-language narrative from the accumulated
-- snapshot history.
--
-- Apply with:
--   wrangler d1 execute billboardiq-db --remote --file=schema/006_traffic_snapshots.sql

CREATE TABLE traffic_snapshots (
  id TEXT PRIMARY KEY,
  billboard_id TEXT NOT NULL REFERENCES billboards(id) ON DELETE CASCADE,
  captured_at INTEGER NOT NULL,
  congestion_score INTEGER,
  density_label TEXT,
  note TEXT,
  created_at INTEGER NOT NULL
);

CREATE INDEX idx_traffic_snapshots_billboard ON traffic_snapshots(billboard_id, captured_at);

ALTER TABLE billboards ADD COLUMN facing TEXT;
ALTER TABLE billboards ADD COLUMN ai_insights TEXT;
ALTER TABLE billboards ADD COLUMN ai_insights_updated_at INTEGER;
