/* ================================================================
   BillboardIQ Traffic Analytics Engine — Cloudflare Worker
   Cron-triggered. For every approved billboard:
     1. Screenshot Google Maps' live traffic layer at its coordinates
        (Browser Rendering — see wrangler.toml [browser] binding).
     2. Store the screenshot in D1 (pending_snapshots) for analysis.

   POC MODE: capture only. The Claude vision/narrative calls below
   (analyzeScreenshot, refreshInsightIfDue) are fully built but NOT
   invoked from scheduled() right now — per the user's call, analysis
   is done interactively through a Claude Code session against the
   pending_snapshots queue instead of a billed API integration, until
   commercial launch. Re-wire them into scheduled() (and set
   ANTHROPIC_API_KEY) at that point; no other changes should be needed.

   Fires hourly; only acts during the 6 target Colombo-local sampling
   slots so a single cron line covers all of them.
   ================================================================ */

import puppeteer from '@cloudflare/puppeteer';

const TARGET_HOURS_LOCAL = [6, 9, 12, 15, 18, 21]; // Colombo time (UTC+5:30)
const COLOMBO_OFFSET_MINUTES = 5 * 60 + 30;
const CLAUDE_MODEL = 'claude-opus-4-8';
const MAX_CONCURRENT_BROWSERS = 3;
const INSIGHT_REFRESH_DAYS = 7;
const INSIGHT_MIN_NEW_SNAPSHOTS = 20;
const PENDING_RETENTION_DAYS = 7; // safety net if pending_snapshots isn't processed for a while

function colomboLocalHour(date) {
  const utcMinutes = date.getUTCHours() * 60 + date.getUTCMinutes();
  const localMinutes = (utcMinutes + COLOMBO_OFFSET_MINUTES) % (24 * 60);
  return Math.floor(localMinutes / 60);
}

function shortId() {
  const bytes = crypto.getRandomValues(new Uint8Array(4));
  return [...bytes].map(b => b.toString(36).toUpperCase().padStart(2, '0')).join('').slice(0, 6);
}

function arrayBufferToBase64(buf) {
  let binary = '';
  const bytes = new Uint8Array(buf);
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

// Analyzes one traffic-layer screenshot. Structured output guarantees the
// first (only) text block is valid JSON matching this schema.
async function analyzeScreenshot(env, imageBase64) {
  const resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json'
    },
    body: JSON.stringify({
      model: CLAUDE_MODEL,
      max_tokens: 400,
      output_config: {
        format: {
          type: 'json_schema',
          schema: {
            type: 'object',
            properties: {
              congestionScore: { type: 'integer' },
              densityLabel: { type: 'string', enum: ['free', 'moderate', 'heavy'] },
              note: { type: 'string' }
            },
            required: ['congestionScore', 'densityLabel', 'note'],
            additionalProperties: false
          }
        }
      },
      messages: [{
        role: 'user',
        content: [
          { type: 'image', source: { type: 'base64', media_type: 'image/jpeg', data: imageBase64 } },
          {
            type: 'text',
            text: 'This is a screenshot of Google Maps with the live traffic layer enabled, centered on a billboard location. ' +
              'Read the colored road segments (green = free-flowing, yellow/orange = moderate, red = heavy congestion) visible ' +
              'in roughly a 500m radius around the center of the image. Estimate an overall congestion score from 0 (completely ' +
              'free-flowing) to 100 (gridlocked), pick the closest density label, and write one short sentence describing what ' +
              'you see (which roads are congested, if any). If no colored traffic data is visible at all, use congestionScore 0, ' +
              'densityLabel "free", and say so in the note.'
          }
        ]
      }]
    })
  });
  if (!resp.ok) throw new Error('Claude vision call failed: ' + resp.status + ' ' + (await resp.text()));
  const data = await resp.json();
  const textBlock = (data.content || []).find(b => b.type === 'text');
  if (!textBlock) throw new Error('No text block in Claude response');
  return JSON.parse(textBlock.text);
}

// Screenshots Google Maps' traffic layer at (lat, lng) using Browser Rendering.
// The `!5m1!1e1` URL fragment is an unofficial, undocumented way to force the
// traffic layer on when loading Maps directly — it can silently break if
// Google changes their URL scheme; this whole approach automates Google's
// consumer web UI rather than a supported Maps Platform API (see schema/006
// migration note and this session's plan for the full caveat).
async function captureTrafficScreenshot(env, lat, lng) {
  const browser = await puppeteer.launch(env.BROWSER);
  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 900, height: 700 });
    const url = `https://www.google.com/maps/@${lat},${lng},17z/data=!5m1!1e1`;
    await page.goto(url, { waitUntil: 'networkidle0', timeout: 30000 });

    // A fresh (cookieless) Browser Rendering session gets Google's cookie-consent
    // interstitial instead of the map on first load — dismiss it or every
    // screenshot captures the dialog, not traffic data.
    const dismissed = await page.evaluate(() => {
      const btn = Array.from(document.querySelectorAll('button'))
        .find(b => /^(accept all|reject all)$/i.test((b.textContent || '').trim()));
      if (btn) { btn.click(); return true; }
      return false;
    }).catch(() => false);
    if (dismissed) {
      await page.waitForNavigation({ waitUntil: 'networkidle0', timeout: 15000 }).catch(() => {});
    }

    // Give traffic tiles a moment to render after the network goes idle.
    await new Promise(r => setTimeout(r, 2500));
    const screenshot = await page.screenshot({ type: 'jpeg', quality: 70 });
    return screenshot;
  } finally {
    await browser.close();
  }
}

// Captures a traffic-layer screenshot and queues it in pending_snapshots for
// analysis (interactive, via Claude Code — see file header). Replaces the
// old capture+analyze-inline flow: no Claude call happens here for now.
async function captureAndQueue(env, billboard) {
  let screenshot;
  try {
    screenshot = await captureTrafficScreenshot(env, billboard.lat, billboard.lng);
  } catch (e) {
    console.error('Screenshot failed for', billboard.id, e.message);
    return;
  }

  const now = Date.now();
  const base64 = arrayBufferToBase64(screenshot);
  await env.DB.prepare(
    `INSERT INTO pending_snapshots (id, billboard_id, captured_at, image_data, created_at)
     VALUES (?,?,?,?,?)`
  ).bind(
    'PS-' + shortId(),
    billboard.id,
    now,
    'data:image/jpeg;base64,' + base64,
    now
  ).run();
}

// Turns a billboard's accumulated snapshot history into a short plain-language
// narrative, refreshed at most every INSIGHT_REFRESH_DAYS or after enough new
// snapshots accumulate — this is a text-only call, no image involved.
async function refreshInsightIfDue(env, billboard) {
  const now = Date.now();
  const lastUpdate = billboard.ai_insights_updated_at || 0;
  const dueByAge = now - lastUpdate > INSIGHT_REFRESH_DAYS * 86400000;

  const countRow = await env.DB.prepare(
    'SELECT COUNT(*) AS n FROM traffic_snapshots WHERE billboard_id=? AND captured_at > ?'
  ).bind(billboard.id, lastUpdate).first();
  const dueByVolume = (countRow?.n || 0) >= INSIGHT_MIN_NEW_SNAPSHOTS;

  if (!dueByAge && !dueByVolume) return;

  const rows = await env.DB.prepare(
    'SELECT captured_at, congestion_score, density_label FROM traffic_snapshots WHERE billboard_id=? ORDER BY captured_at DESC LIMIT 200'
  ).bind(billboard.id).all();
  const snapshots = rows.results || [];
  if (snapshots.length < 5) return; // not enough history yet to say anything useful

  const summary = snapshots.map(s => {
    const d = new Date(s.captured_at);
    return `${d.toISOString().slice(0, 16).replace('T', ' ')} — score ${s.congestion_score} (${s.density_label})`;
  }).join('\n');

  const resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json'
    },
    body: JSON.stringify({
      model: CLAUDE_MODEL,
      max_tokens: 300,
      messages: [{
        role: 'user',
        content: `You're helping an outdoor-advertising provider judge a billboard location at "${billboard.title}" ` +
          `(${billboard.area}), a ${billboard.type} billboard priced at LKR ${billboard.price}/month with a stated ` +
          `daily traffic estimate of ${billboard.traffic} vehicles/day. Below is its recent collected traffic-congestion ` +
          `history (0-100 congestion score, sampled a few times a day):\n\n${summary}\n\n` +
          'Write 2-3 short sentences of plain-language findings and a recommendation — call out any clear peak-hour ' +
          'pattern, note the overall congestion level, and say what that implies for billboard visibility/value. ' +
          'No headers, no bullet points, just prose a busy provider can skim.'
      }]
    })
  });
  if (!resp.ok) { console.error('Insight call failed for', billboard.id, resp.status); return; }
  const data = await resp.json();
  const textBlock = (data.content || []).find(b => b.type === 'text');
  if (!textBlock) return;

  await env.DB.prepare('UPDATE billboards SET ai_insights=?, ai_insights_updated_at=? WHERE id=?')
    .bind(textBlock.text.trim().slice(0, 2000), now, billboard.id)
    .run();
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
    const hour = colomboLocalHour(new Date(event.scheduledTime || Date.now()));
    if (!TARGET_HOURS_LOCAL.includes(hour)) return; // not one of the 6 sampling slots

    // Safety net: drop any screenshot that's sat unprocessed too long, so an
    // interactive-analysis gap doesn't grow the DB unbounded.
    await env.DB.prepare('DELETE FROM pending_snapshots WHERE created_at < ?')
      .bind(Date.now() - PENDING_RETENTION_DAYS * 86400000)
      .run();

    const rows = await env.DB.prepare(
      "SELECT id, lat, lng FROM billboards WHERE approval_state='approved'"
    ).all();
    const billboards = rows.results || [];
    if (!billboards.length) return;

    await runBatch(billboards, MAX_CONCURRENT_BROWSERS, b => captureAndQueue(env, b));

    // analyzeScreenshot()/refreshInsightIfDue() intentionally not called here — see file header.
  }
};
