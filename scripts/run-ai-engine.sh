#!/bin/bash
# Processes queued traffic screenshots (pending_snapshots) into real
# congestion data (traffic_snapshots) using a headless Claude Code run —
# no billed Anthropic API key involved, uses this machine's Claude Code
# session instead. Triggered by typing `RUN AI ENGINE` in any terminal
# (see the `RUN` function in ~/.zshrc).
set -euo pipefail
cd "$(dirname "$0")/.."

PROMPT='You are processing the BillboardIQ traffic-analytics queue. Working
directory is the billboardiq project root.

1. Run: wrangler d1 execute billboardiq-db --remote --command "SELECT id, billboard_id, captured_at, image_data FROM pending_snapshots" --json
   If it returns zero rows, say "No pending snapshots." and stop — do nothing else.

2. For each row: decode the image_data (a data:image/jpeg;base64,... URL) to a
   temporary jpg file, then read/view that image. It is a screenshot of Google
   Maps with the live traffic layer enabled, centered on a billboard location.
   Read the colored road segments (green = free-flowing, yellow/orange =
   moderate, red = heavy congestion) visible in roughly a 500m radius around
   the center of the image. Estimate an overall congestion score from 0
   (completely free-flowing) to 100 (gridlocked), pick the closest density
   label (free/moderate/heavy), and write one short sentence describing what
   you see. If the image is not a usable traffic screenshot (e.g. it shows a
   cookie-consent dialog, an error page, or no map at all), skip it — do not
   invent a score — and just delete that pending_snapshots row without
   inserting into traffic_snapshots.

3. For each successfully analyzed image, insert one row into traffic_snapshots
   via wrangler d1 execute:
   INSERT INTO traffic_snapshots (id, billboard_id, captured_at, congestion_score, density_label, note, created_at)
   VALUES ('"'"'TS-<6 random uppercase alphanumeric chars>'"'"', <billboard_id>, <captured_at>, <score>, '"'"'<label>'"'"', '"'"'<note>'"'"', <now_epoch_ms>)

4. After each row is handled (whether analyzed or skipped), delete it from
   pending_snapshots by id, and delete any temp image file you created.

5. When finished, print a one-line summary: how many snapshots were analyzed
   vs skipped, and which billboards they belonged to.

Do not fabricate data for anything you could not actually read. Do not touch
any other table.'

claude -p "$PROMPT" --permission-mode bypassPermissions
