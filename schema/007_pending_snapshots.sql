-- Holding area for screenshots captured automatically by the traffic-engine
-- Worker (worker/) while the POC runs without a paid Claude API key —
-- analysis happens interactively instead (see conversation). A row here is
-- transient: captured by the Worker, then read/analyzed/deleted by hand
-- (or by a scheduled Claude session) — nothing here is meant to persist
-- long-term, unlike traffic_snapshots.
--
-- Apply with:
--   wrangler d1 execute billboardiq-db --remote --file=schema/007_pending_snapshots.sql

CREATE TABLE pending_snapshots (
  id TEXT PRIMARY KEY,
  billboard_id TEXT NOT NULL REFERENCES billboards(id) ON DELETE CASCADE,
  captured_at INTEGER NOT NULL,
  image_data TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX idx_pending_snapshots_billboard ON pending_snapshots(billboard_id, captured_at);
