-- Lets any signed-in user (any role) favorite/save a billboard from the
-- public map. Purely a join table — no columns added to billboards itself,
-- so favoriting never touches the row a provider/agent is editing.
--
-- Apply with:
--   wrangler d1 execute billboardiq-db --remote --file=schema/010_favorites.sql

CREATE TABLE favorites (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  billboard_id TEXT NOT NULL REFERENCES billboards(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, billboard_id)
);

CREATE INDEX idx_favorites_billboard ON favorites(billboard_id);
