-- Replaces the screenshot+vision-guessed traffic pipeline with real numeric
-- data from Google Routes API. Each approved billboard gets a fixed traffic
-- segment (two points a few hundred meters apart, straddling its location
-- along the road it faces) resolved once and reused forever; the Worker then
-- asks Google for that segment's live vs. free-flow travel duration on every
-- sampling tick and derives congestion_score directly from the ratio — no
-- image, no LLM guess, anywhere in the loop. See worker/src/index.js.
--
-- Apply with:
--   wrangler d1 execute billboardiq-db --remote --file=schema/012_traffic_segments.sql

ALTER TABLE billboards ADD COLUMN traffic_seg_origin_lat REAL;
ALTER TABLE billboards ADD COLUMN traffic_seg_origin_lng REAL;
ALTER TABLE billboards ADD COLUMN traffic_seg_dest_lat REAL;
ALTER TABLE billboards ADD COLUMN traffic_seg_dest_lng REAL;
ALTER TABLE billboards ADD COLUMN traffic_seg_resolved_at INTEGER;

-- raw_duration_s / raw_static_duration_s are the actual seconds Google
-- returned (live vs. traffic-free) for the segment at capture time — kept so
-- every congestion_score is independently checkable against the real numbers
-- behind it, not just trusted as a black-box figure.
ALTER TABLE traffic_snapshots ADD COLUMN source TEXT NOT NULL DEFAULT 'vision_legacy';
ALTER TABLE traffic_snapshots ADD COLUMN raw_duration_s INTEGER;
ALTER TABLE traffic_snapshots ADD COLUMN raw_static_duration_s INTEGER;

-- The screenshot-staging queue is obsolete now that sampling writes
-- straight into traffic_snapshots with no interactive analysis step.
DROP TABLE IF EXISTS pending_snapshots;
