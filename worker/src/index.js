/* ================================================================
   BillboardIQ Traffic Analytics Engine — Cloudflare Worker
   Cron-triggered. For every approved billboard:
     1. Resolve a fixed "traffic segment" — two points ~600m apart,
        straddling the billboard along the road it faces — once, the first
        time the billboard is seen. Cached forever after in
        billboards.traffic_seg_* so every later sample queries the exact
        same physical stretch of road.
     2. On each due tick, ask Google Routes API for that segment's live
        traffic-aware duration vs. its traffic-free baseline duration in a
        single call. congestion_score is derived directly from that ratio —
        a real number from Google's own traffic model, not a screenshot an
        LLM has to guess at. Replaces the old screenshot+vision pipeline
        entirely (see git history for that approach and why it was dropped:
        it scraped Google's consumer Maps UI via an undocumented URL trick,
        got blocked by bot detection ~1 in 5 tries, and never had a real
        number anywhere in the loop).

   Fires every 15 minutes. Each billboard is sampled 4x/hour (every tick)
   during its own declared peak hours — or a default school/office pattern
   (8, 9, 14, 17, 18) if it hasn't declared any — and just once/hour
   otherwise, matching the old baseline cadence off-peak. This is denser
   sampling exactly where the traffic actually varies hour-to-hour, without
   quadrupling Routes API usage across the whole day.

   Does NOT generate the plain-language ai_insights narrative — that's a
   separate, on-demand step (scripts/run-ai-insights.sh, triggered by typing
   `RUN AI ENGINE`) so it costs nothing beyond this machine's existing Claude
   Code session, instead of a billed Anthropic API key running automatically
   on every cron tick.
   ================================================================ */

const MAX_CONCURRENT_REQUESTS = 4;
const COLOMBO_OFFSET_MINUTES = 5 * 60 + 30;
const DEFAULT_PEAK_HOURS = [8, 9, 14, 17, 18]; // school/office commute pattern, used when a billboard hasn't declared its own
const SEGMENT_OFFSET_METERS = 300; // each segment endpoint sits this far from the billboard, so the route through it is ~600m
const COMPASS_BEARINGS = { N: 0, NE: 45, E: 90, SE: 135, S: 180, SW: 225, W: 270, NW: 315 };

function colomboLocalParts(date) {
  const utcMinutes = date.getUTCHours() * 60 + date.getUTCMinutes();
  const localMinutes = (utcMinutes + COLOMBO_OFFSET_MINUTES) % (24 * 60);
  return { hour: Math.floor(localMinutes / 60), minute: localMinutes % 60 };
}

function shortId() {
  const bytes = crypto.getRandomValues(new Uint8Array(4));
  return [...bytes].map(b => b.toString(36).toUpperCase().padStart(2, '0')).join('').slice(0, 6);
}

// Great-circle destination point `distanceMeters` from (lat, lng) along `bearingDeg`.
function destinationPoint(lat, lng, bearingDeg, distanceMeters) {
  const R = 6371000;
  const bearing = bearingDeg * Math.PI / 180;
  const lat1 = lat * Math.PI / 180, lng1 = lng * Math.PI / 180;
  const angDist = distanceMeters / R;
  const lat2 = Math.asin(Math.sin(lat1) * Math.cos(angDist) + Math.cos(lat1) * Math.sin(angDist) * Math.cos(bearing));
  const lng2 = lng1 + Math.atan2(
    Math.sin(bearing) * Math.sin(angDist) * Math.cos(lat1),
    Math.cos(angDist) - Math.sin(lat1) * Math.sin(lat2)
  );
  return { lat: lat2 * 180 / Math.PI, lng: ((lng2 * 180 / Math.PI + 540) % 360) - 180 };
}

function parseSeconds(durationStr) {
  // Routes API durations are strings like "165s".
  if (!durationStr) return null;
  const n = parseInt(durationStr, 10);
  return Number.isFinite(n) ? n : null;
}

// One Routes API computeRoutes call. `trafficAware=false` (used only for
// one-time segment resolution, below) is billed at the cheaper tier since no
// live traffic is requested — just the routed distance.
async function computeRoutes(env, origin, dest, trafficAware, fieldMask) {
  const resp = await fetch('https://routes.googleapis.com/directions/v2:computeRoutes', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Goog-Api-Key': env.GOOGLE_MAPS_SERVER_KEY,
      'X-Goog-FieldMask': fieldMask
    },
    body: JSON.stringify({
      origin: { location: { latLng: { latitude: origin.lat, longitude: origin.lng } } },
      destination: { location: { latLng: { latitude: dest.lat, longitude: dest.lng } } },
      travelMode: 'DRIVE',
      routingPreference: trafficAware ? 'TRAFFIC_AWARE' : 'TRAFFIC_UNAWARE'
    })
  });
  if (!resp.ok) throw new Error('Routes API failed: ' + resp.status + ' ' + (await resp.text()));
  const data = await resp.json();
  const route = (data.routes || [])[0];
  if (!route) throw new Error('No route found');
  return route;
}

// Resolves and caches a billboard's fixed traffic segment — two points
// SEGMENT_OFFSET_METERS apart, straddling its coordinates. If `facing` is
// set (from the Add Billboard form), the segment runs along that bearing.
// If not, four cardinal bearings are probed and whichever one's actual
// routed distance is closest to the straight-line distance is kept — that's
// the one following a real nearby road rather than detouring, so a missing
// `facing` never requires a manual input to work around.
async function resolveSegment(env, billboard) {
  const bearings = (billboard.facing && COMPASS_BEARINGS[billboard.facing] !== undefined)
    ? [COMPASS_BEARINGS[billboard.facing]]
    : [0, 90, 180, 270];

  let best = null;
  for (const bearing of bearings) {
    const origin = destinationPoint(billboard.lat, billboard.lng, (bearing + 180) % 360, SEGMENT_OFFSET_METERS);
    const dest = destinationPoint(billboard.lat, billboard.lng, bearing, SEGMENT_OFFSET_METERS);
    try {
      const route = await computeRoutes(env, origin, dest, false, 'routes.distanceMeters');
      const straightLine = SEGMENT_OFFSET_METERS * 2;
      const detour = route.distanceMeters ? route.distanceMeters / straightLine : Infinity;
      if (!best || detour < best.detour) best = { origin, dest, detour };
    } catch (e) {
      console.error('Segment probe failed for', billboard.id, 'bearing', bearing, e.message);
    }
  }
  if (!best) {
    console.error('Could not resolve traffic segment for', billboard.id);
    return;
  }

  const now = Date.now();
  await env.DB.prepare(
    `UPDATE billboards SET traffic_seg_origin_lat=?, traffic_seg_origin_lng=?, traffic_seg_dest_lat=?, traffic_seg_dest_lng=?, traffic_seg_resolved_at=? WHERE id=?`
  ).bind(best.origin.lat, best.origin.lng, best.dest.lat, best.dest.lng, now, billboard.id).run();

  billboard.traffic_seg_origin_lat = best.origin.lat;
  billboard.traffic_seg_origin_lng = best.origin.lng;
  billboard.traffic_seg_dest_lat = best.dest.lat;
  billboard.traffic_seg_dest_lng = best.dest.lng;
  billboard.traffic_seg_resolved_at = now;
}

// Samples one billboard's resolved segment for live vs. free-flow duration
// and writes the derived score straight into traffic_snapshots.
// congestionScore = % slower than free-flow, capped at 100 — 50% slower
// crosses into "heavy" and 85% slower into "severe", matching the
// thresholds dashboard.html/index.html already hardcode in labelForScore().
async function sampleLiveTraffic(env, billboard) {
  if (!billboard.traffic_seg_resolved_at) return; // resolution failed this tick; try again next tick

  const origin = { lat: billboard.traffic_seg_origin_lat, lng: billboard.traffic_seg_origin_lng };
  const dest = { lat: billboard.traffic_seg_dest_lat, lng: billboard.traffic_seg_dest_lng };

  let route;
  try {
    route = await computeRoutes(env, origin, dest, true, 'routes.duration,routes.staticDuration');
  } catch (e) {
    console.error('Traffic sample failed for', billboard.id, e.message);
    return;
  }

  const durationS = parseSeconds(route.duration);
  const staticS = parseSeconds(route.staticDuration);
  if (!durationS || !staticS || staticS <= 0) return;

  const pctSlower = (durationS / staticS - 1) * 100;
  const score = Math.max(0, Math.min(100, Math.round(pctSlower)));
  const label = score >= 85 ? 'severe' : score >= 50 ? 'heavy' : 'free';
  const note = pctSlower > 1
    ? `Live travel time ${durationS}s vs ${staticS}s free-flow — ${Math.round(pctSlower)}% slower than normal.`
    : `Live travel time ${durationS}s vs ${staticS}s free-flow — near free-flow.`;

  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO traffic_snapshots (id, billboard_id, captured_at, congestion_score, density_label, note, created_at, source, raw_duration_s, raw_static_duration_s)
     VALUES (?,?,?,?,?,?,?,?,?,?)`
  ).bind('TS-' + shortId(), billboard.id, now, score, label, note, now, 'google_routes', durationS, staticS).run();
}

// Fisher-Yates shuffle — spreads which billboard runs out of tick
// time/budget last evenly across all active billboards, instead of it
// always being the one that happens to sort last.
function shuffled(arr) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

async function runBatch(items, limit, fn) {
  let i = 0;
  async function worker() {
    while (i < items.length) {
      const item = items[i++];
      await fn(item);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
}

export default {
  async scheduled(event, env, ctx) {
    const { hour, minute } = colomboLocalParts(new Date(event.scheduledTime || Date.now()));

    // Excludes simulated companies (companies.is_test_data — seeded via the
    // admin console's "Simulate test data" toggle) so fake demo billboards
    // never get sampled against the real Google Routes API or billed for it.
    const rows = await env.DB.prepare(
      `SELECT b.id, b.lat, b.lng, b.facing, b.peak_hours,
              b.traffic_seg_origin_lat, b.traffic_seg_origin_lng, b.traffic_seg_dest_lat, b.traffic_seg_dest_lng, b.traffic_seg_resolved_at
       FROM billboards b LEFT JOIN companies c ON c.id = b.company_id
       WHERE b.approval_state='approved' AND COALESCE(c.is_test_data, 0) = 0`
    ).all();
    const billboards = rows.results || [];
    if (!billboards.length) return;

    // Resolve (once, cached) any billboard that doesn't have a traffic
    // segment yet — new listings, or ones whose earlier probe attempt failed.
    const unresolved = billboards.filter(b => !b.traffic_seg_resolved_at);
    await runBatch(unresolved, MAX_CONCURRENT_REQUESTS, b => resolveSegment(env, b));

    // Peak hours: sample on every 15-min tick. Off-peak: only the :00 tick,
    // so non-peak sampling stays at the old 1x/hour baseline instead of
    // quadrupling everywhere.
    const due = billboards.filter(b => {
      let peak;
      try { peak = JSON.parse(b.peak_hours || '[]'); } catch (e) { peak = []; }
      if (!peak.length) peak = DEFAULT_PEAK_HOURS;
      return peak.includes(hour) || minute === 0;
    });
    await runBatch(shuffled(due), MAX_CONCURRENT_REQUESTS, b => sampleLiveTraffic(env, b));

    // The plain-language ai_insights narrative is generated separately, on
    // demand, via `RUN AI ENGINE` in a terminal (see scripts/run-ai-insights.sh)
    // — that uses this machine's Claude Code session instead of a billed
    // Anthropic API key, same reasoning as the original screenshot-analysis
    // pipeline this Worker replaced.
  }
};
