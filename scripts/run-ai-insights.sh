#!/bin/bash
# Refreshes each approved billboard's plain-language ai_insights narrative
# from its real traffic_snapshots history (Google Routes data — see
# worker/src/index.js) using a headless Claude Code run — no billed
# Anthropic API key involved, uses this machine's Claude Code session
# instead. Triggered by typing `RUN AI ENGINE` in any terminal (see the
# `RUN` function in ~/.zshrc). The Worker's own cron never calls a billed
# API for this; it only writes real traffic scores.
set -euo pipefail
cd "$(dirname "$0")/.."

PROMPT='You are refreshing BillboardIQ'"'"'s plain-language traffic-insight
narratives. Working directory is the billboardiq project root.

1. Run: wrangler d1 execute billboardiq-db --remote --command "SELECT b.id, b.title, b.area, b.type, b.price, b.traffic, b.ai_insights_updated_at FROM billboards b LEFT JOIN companies c ON c.id=b.company_id WHERE b.approval_state='"'"'approved'"'"' AND COALESCE(c.is_test_data,0)=0" --json

2. For each billboard from step 1, a refresh is due if ai_insights_updated_at
   is null, OR is more than 7 days (604800000 ms) before now, OR running
   wrangler d1 execute billboardiq-db --remote --command "SELECT COUNT(*) AS n FROM traffic_snapshots WHERE billboard_id='"'"'<id>'"'"' AND captured_at > <ai_insights_updated_at or 0>" --json
   returns n >= 20. Skip billboards that are not due — do nothing for them.

3. For each due billboard, run: wrangler d1 execute billboardiq-db --remote --command "SELECT captured_at, congestion_score, density_label FROM traffic_snapshots WHERE billboard_id='"'"'<id>'"'"' ORDER BY captured_at DESC LIMIT 200" --json
   If fewer than 5 rows come back, skip it — not enough real history yet to
   say anything useful. Do not invent data to fill the gap.

4. From that real history (0-100 congestion scores, sampled a few times a
   day, straight from Google'"'"'s live-traffic routing data), write 2-3 short
   sentences of plain-language findings and a recommendation for the
   billboard'"'"'s provider — call out any clear peak-hour pattern visible in
   the actual numbers, note the overall congestion level, and say what that
   implies for billboard visibility/value. No headers, no bullet points,
   just prose a busy provider can skim. Base this only on the numbers you
   were actually given — never invent or embellish a pattern that isn'"'"'t
   really there.

5. Write the result back with: wrangler d1 execute billboardiq-db --remote --command "UPDATE billboards SET ai_insights='"'"'<your text, single-quotes inside it doubled for SQL escaping>'"'"', ai_insights_updated_at=<current epoch ms> WHERE id='"'"'<id>'"'"'"

6. When finished, print a one-line summary: how many billboards were
   refreshed vs. skipped, and which ones.

Do not touch traffic_snapshots, traffic_seg_*, or any other table/column —
only billboards.ai_insights and billboards.ai_insights_updated_at.'

claude -p "$PROMPT" --permission-mode bypassPermissions
