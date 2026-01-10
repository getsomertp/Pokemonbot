// src/server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { execSync } = require("child_process");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const WebSocket = require("ws");
const path = require("path");

const { prisma } = require("./prisma");
const { Game } = require("./game");
const { envInt } = require("./util");
const { startKickReader } = require("./kickRead");
const dex = require("./dex");
const { sendKickChatMessage, refreshAccessToken } = require("./kickSend");
const { getKickTokens, setKickTokens, getNeedsAuth, clearNeedsAuth, normStreamer, markNeedsAuth } = require("./tokenStore");

const app = express();
app.set("trust proxy", 1); // IMPORTANT for Railway (correct https in req.protocol)

app.use(cors());
app.use(express.json());
app.use(cookieParser(process.env.COOKIE_SECRET || "dev_cookie_secret"));

// Static assets for OBS overlay (sounds, images, etc)
app.use("/sounds", express.static(path.join(__dirname, "..", "public", "sounds")));

// Static assets (OBS overlay sounds, etc.)
app.use(express.static(path.join(__dirname, "..", "public")));

const PORT = Number(process.env.PORT || 3000);
const PREFIX = process.env.COMMAND_PREFIX || "!";
const KICK_CHANNEL = process.env.KICK_CHANNEL;
const KICK_CHANNELS = String(process.env.KICK_CHANNELS || KICK_CHANNEL || "")
  .split(",")
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);
const PRIMARY_CHANNEL = KICK_CHANNELS[0] || (KICK_CHANNEL || "").toLowerCase();
const STREAMER_USERNAME = (process.env.STREAMER_USERNAME || PRIMARY_CHANNEL || "").toLowerCase();

const game = new Game();

// ---- Trainer vs Trainer duels (in-memory challenge/accept) ----
// Map: opponentHandleLower -> { challengerHandleLower, challengerName, challengerPlatformUserId, createdAt }
const duelRequests = new Map();
const DUEL_TTL_MS = 60 * 1000; // 60s to accept

// ---- Readiness / health (helps avoid Railway 502 confusion) ----
let READY = false;
let BOOT_ERROR = null;

// ---- Overlay (OBS Browser Source) ----
let overlayWss = null;
let overlayLastSpawn = null;
// In-memory overlay event queue (WebSocket + polling fallback)
let overlaySeq = 0;
const overlayQueue = [];
const OVERLAY_QUEUE_MAX = 40;

// Overlay sound settings (stored in Prisma Setting table)
function soundKey(streamer, part) {
  const s = normStreamer(streamer || PRIMARY_CHANNEL);
  return `overlay:${s}:sound:${part}`;
}

async function getSoundSettings(streamer) {
  const s = normStreamer(streamer || PRIMARY_CHANNEL);
  const [enabledRow, volumeRow] = await Promise.all([
    prisma.setting.findUnique({ where: { key: soundKey(s, "enabled") } }),
    prisma.setting.findUnique({ where: { key: soundKey(s, "volume") } })
  ]);
  const enabled = enabledRow?.value != null ? enabledRow.value === "1" : true;
  const volume = volumeRow?.value != null ? Math.max(0, Math.min(1, Number(volumeRow.value))) : 0.5;
  return { streamer: s, enabled, volume };
}

async function setSoundSettings(streamer, { enabled, volume }) {
  const s = normStreamer(streamer || PRIMARY_CHANNEL);
  if (!s) return { streamer: s, enabled: true, volume: 0.5 };

  if (enabled != null) {
    await prisma.setting.upsert({
      where: { key: soundKey(s, "enabled") },
      update: { value: enabled ? "1" : "0" },
      create: { key: soundKey(s, "enabled"), value: enabled ? "1" : "0" }
    });
  }
  if (volume != null) {
    const v = Math.max(0, Math.min(1, Number(volume)));
    await prisma.setting.upsert({
      where: { key: soundKey(s, "volume") },
      update: { value: String(v) },
      create: { key: soundKey(s, "volume"), value: String(v) }
    });
  }

  const cur = await getSoundSettings(s);
  overlayBroadcast({ type: "sound_settings", settings: cur });
  return cur;
}

// ---- Economy (leaderpoints) + Betting ----
// Wagering uses the SAME currency as the leaderboard: pointsEarned ("leaderpoints").
// We can't subtract from Catch rows (they are history), so we store a per-user adjustment
// in the Setting table and include it in totals.
// Keys:
//  - lp_adj:<userId> => signed integer adjustment added to sum(pointsEarned)

function lpAdjKey(userId) {
  return `lp_adj:${userId}`;
}

async function getLpAdj(userId) {
  const row = await prisma.setting.findUnique({ where: { key: lpAdjKey(userId) } });
  if (!row?.value) return 0;
  const n = Number(row.value);
  return Number.isFinite(n) ? Math.trunc(n) : 0;
}

async function setLpAdj(userId, amount) {
  const n = Math.trunc(Number(amount) || 0);
  await prisma.setting.upsert({
    where: { key: lpAdjKey(userId) },
    update: { value: String(n) },
    create: { key: lpAdjKey(userId), value: String(n) }
  });
  return n;
}

async function addLpAdj(userId, delta) {
  const cur = await getLpAdj(userId);
  return setLpAdj(userId, cur + (Math.trunc(Number(delta) || 0)));
}

async function getLeaderPoints(userId) {
  const agg = await prisma.catch.aggregate({ where: { userId }, _sum: { pointsEarned: true } });
  const base = agg?._sum?.pointsEarned || 0;
  const adj = await getLpAdj(userId);
  return base + adj;
}
function payoutMultiplierForSpawn(spawn) {
  // Tune to taste via env vars later.
  const tier = String(spawn?.tier || "common").toLowerCase();
  const baseByTier = {
    common: 1.5,
    uncommon: 2,
    rare: 3,
    epic: 5,
    legendary: 8
  };
  const base = baseByTier[tier] || 1.5;
  const shinyMult = spawn?.isShiny ? 3 : 1;
  return base * shinyMult;
}


function spriteUrlForSpawn(spawn) {
  try {
    if (!spawn) return null;
    const d = dex.loadDex();
    const mon = d.pokemon.find((x) => x.id === spawn.pokemonId) || d.pokemon.find((x) => x.name === spawn.pokemon);
    const dexNum = mon?.dex;
    if (!dexNum) return null;
    const base = 'https://raw.githubusercontent.com/PokeAPI/sprites/master/sprites/pokemon';
    if (spawn.isShiny) return `${base}/shiny/${dexNum}.png`;
    return `${base}/${dexNum}.png`;
  } catch {
    return null;
  }
}

function spriteUrlForName(name, { shiny = false } = {}) {
  try {
    if (!name) return null;
    const d = dex.loadDex();
    const mon = d.pokemon.find((x) => String(x.name).toLowerCase() === String(name).toLowerCase()) || d.pokemon.find((x) => x.id === name);
    const dexNum = mon?.dex;
    if (!dexNum) return null;
    const base = 'https://raw.githubusercontent.com/PokeAPI/sprites/master/sprites/pokemon';
    if (shiny) return `${base}/shiny/${dexNum}.png`;
    return `${base}/${dexNum}.png`;
  } catch {
    return null;
  }
}


function overlayEventFromSpawn(spawn) {
  if (!spawn) return { type: 'clear' };
  return {
    type: 'spawn',
    spawn: {
      id: spawn.id,
      name: spawn.pokemon,
      tier: spawn.tier,
      isShiny: !!spawn.isShiny,
      level: spawn.level || 5,
      sprite: spriteUrlForSpawn(spawn),
      spawnedAt: spawn.spawnedAt,
      expiresAt: spawn.expiresAt
    }
  };
}

function overlayBroadcast(event) {
  try {
    // Stamp event with a monotonic id so the overlay can poll reliably.
    // We still send over WebSocket when available.
    overlaySeq += 1;
    const stamped = Object.assign({ _id: overlaySeq }, event || {});
    overlayQueue.push(stamped);
    while (overlayQueue.length > OVERLAY_QUEUE_MAX) overlayQueue.shift();

    if (!overlayWss) return;
    const payload = JSON.stringify(stamped);
    for (const client of overlayWss.clients) {
      if (client.readyState === 1) client.send(payload);
    }
  } catch {}
}

// Polling fallback for OBS browser sources where WS upgrades might be blocked.
app.get('/overlay/poll', (req, res) => {
  try {
    const since = Number(req.query.since || 0);
    const evs = overlayQueue.filter(e => (Number(e?._id) || 0) > since);
    res.json({ ok: true, now: overlaySeq, events: evs });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'internal_error' });
  }
});

app.get("/", (req, res) => res.status(200).send("ok"));

// Handy helper page to start Kick OAuth (and avoids multi-line template literal syntax issues)
app.get("/auth/kick", async (req, res) => {
  const baseUrl = getPublicBaseUrl(req);
  const channels = (KICK_CHANNELS && KICK_CHANNELS.length ? KICK_CHANNELS : [PRIMARY_CHANNEL]).filter(Boolean);

  const items = [];
  for (const ch of channels) {
    const tok = await getKickTokens(ch);
    const need = await getNeedsAuth(ch);
    const exp = tok?.expiresAtMs ? Number(tok.expiresAtMs) : 0;
    const expText = exp ? new Date(exp).toISOString() : "(none)";
    const hasRefresh = Boolean(tok?.refreshToken);
    const hasAccess = Boolean(tok?.accessToken);

    const startUrl = `${baseUrl}/auth/kick/start?channel=${encodeURIComponent(ch)}`;

    const statusBits = [];
    statusBits.push(hasAccess ? "access✅" : "access❌");
    statusBits.push(hasRefresh ? "refresh✅" : "refresh❌");
    statusBits.push(`expires: ${expText}`);
    if (need?.needsAuth) statusBits.push(`NEEDS AUTH: ${need.reason || ""}`);

    items.push(
      `<li style="margin:10px 0">` +
        `<b>#${ch}</b> — <code>${statusBits.join(" | ")}</code> ` +
        `<a href="${startUrl}" style="margin-left:10px">(Re)Authorize</a>` +
      `</li>`
    );
  }

  const html = [
    '<!doctype html>',
    '<html>',
    '  <head>',
    '    <meta charset="utf-8" />',
    '    <meta name="viewport" content="width=device-width, initial-scale=1" />',
    '    <title>Kick OAuth</title>',
    '    <style>',
    '      body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:40px;}',
    '      a{display:inline-block;padding:10px 14px;border:1px solid #ddd;border-radius:10px;text-decoration:none;}',
    '      code{background:#f6f6f6;padding:2px 6px;border-radius:6px;}',
    '      li a{padding:6px 10px;}',
    '    </style>',
    '  </head>',
    '  <body>',
    '    <h1>Kick OAuth (PKCE)</h1>',
    '    <p>This page is your re-auth fallback. If token refresh fails, re-authorize here.</p>',
    `    <p><small>PUBLIC_BASE_URL: <code>${baseUrl}</code></small></p>`,
    '    <h3>Channels</h3>',
    `    <ul>${items.join('')}</ul>`,
    '  </body>',
    '</html>'
  ].join("\n");

  res.status(200).type("html").send(html);
});

app.get("/health", (req, res) => {
  // Railway healthchecks should return 200 as soon as the HTTP server is up.
  // Use the `ready` field to see whether DB/OAuth/chat reader have finished booting.
  return res.status(200).json({
    ok: true,
    ready: !!READY,
    ts: Date.now(),
    boot_error: BOOT_ERROR ? String(BOOT_ERROR) : null,
  });
});

process.on("unhandledRejection", (e) => console.error("UNHANDLED REJECTION:", e));
process.on("uncaughtException", (e) => console.error("UNCAUGHT EXCEPTION:", e));

// ---------- DB bootstrap ----------
function ensureDbSchema() {
  // Production-safe: apply committed migrations (no destructive db-push guessing)
  // If there are no migrations yet, don't hard-fail the service; continue booting.
  const cmd = "npx prisma migrate deploy";
  console.log(`Running: ${cmd}`);
  try {
    const out = execSync(cmd, { encoding: "utf8" });
    if (out) process.stdout.write(out);
    console.log("✅ prisma migrate deploy complete");
  } catch (e) {
    const stdout = e?.stdout ? e.stdout.toString() : "";
    const stderr = e?.stderr ? e.stderr.toString() : "";
    if (stdout) process.stdout.write(stdout);
    if (stderr) process.stderr.write(stderr);

    const msg = `${stdout}\n${stderr}\n${e?.message || ""}`;

    // If no migrations exist (common for first deploy), don't crash the whole service.
    // Prisma error text can vary a bit by version.
    const noMigrations =
      msg.includes("No migrations found") ||
      msg.includes("No migration found") ||
      msg.includes("Could not find any migrations") ||
      msg.includes("Could not find a migrations directory") ||
      msg.includes("migrations directory") && msg.includes("not found");

    if (noMigrations) {
      console.warn("⚠️ No Prisma migrations to deploy yet; continuing without applying migrations.");
      return;
    }

    throw e;
  }
}

// ---------- Kick OAuth token auto-refresh ----------
// 1) Automatic refresh before expiry
// 2) Retry logic handled inside refreshAccessToken(...)
// 3) If refresh fails, we mark needs-auth and expose the re-auth page at /auth/kick

async function refreshKickTokenIfNeeded(streamer, { force = false } = {}) {
  try {
    await refreshAccessToken({ streamer: streamer || PRIMARY_CHANNEL, force });
  } catch (e) {
    console.error("Token refresh error:", e?.message || e);
  }
}

function startTokenRefreshLoop() {
  const channels = (KICK_CHANNELS && KICK_CHANNELS.length ? KICK_CHANNELS : [PRIMARY_CHANNEL]).filter(Boolean);

  // Quick loop every 30s to keep tokens fresh (lightweight)
  setInterval(() => {
    for (const ch of channels) {
      refreshKickTokenIfNeeded(ch).catch(() => {});
    }
  }, 30 * 1000);

  // Also kick once at boot
  for (const ch of channels) {
    refreshKickTokenIfNeeded(ch).catch(() => {});
  }
}


async function migrateLegacyKickTokens() {
  try {
    const ch = PRIMARY_CHANNEL;
    if (!ch) return;

    const cur = await getKickTokens(ch);
    if (cur && (cur.refreshToken || cur.accessToken)) return;

    const legacyAccess = await prisma.setting.findUnique({ where: { key: "kick_access_token" } });
    const legacyRefresh = await prisma.setting.findUnique({ where: { key: "kick_refresh_token" } });
    const legacyExp = await prisma.setting.findUnique({ where: { key: "kick_access_expires_at" } });

    if (!legacyAccess?.value && !legacyRefresh?.value) return;

    console.log("♻️ Migrating legacy Kick tokens to per-channel storage...");
    await setKickTokens(ch, {
      accessToken: legacyAccess?.value || null,
      refreshToken: legacyRefresh?.value || null,
      expiresAtMs: legacyExp?.value ? Number(legacyExp.value) : 0,
      scope: process.env.KICK_SCOPES || "user:read chat:write"
    });
    await clearNeedsAuth(ch);
  } catch (e) {
    console.warn("Legacy token migration skipped:", e?.message || e);
  }
}

// ---------- Spawns ----------

function spawnLabel(spawn) {
  const levelTag = spawn?.level ? `Lv. ${spawn.level} ` : "";
  const shinyTag = spawn?.isShiny ? " ✨SHINY✨" : "";
  const tierTag = spawn?.tier ? ` (${spawn.tier})` : "";
  return `${levelTag}${spawn.pokemon}${tierTag}${shinyTag}`;
}

async function announceSpawn(spawn) {
  const msg = `A wild ${spawnLabel(spawn)} appeared! Type ${PREFIX}catch`;

  // Push to OBS overlay
  overlayLastSpawn = spawn;
  overlayBroadcast(overlayEventFromSpawn(spawn));

  // Schedule a despawn event so the overlay (and looping sound) can end exactly
  // when the Pokémon is no longer capturable.
  try {
    const ms = Math.max(0, new Date(spawn.expiresAt).getTime() - Date.now());
    setTimeout(async () => {
      try {
        const active = await game.getActiveSpawn();
        const stillActiveSame = active && active.id === spawn.id;
        if (stillActiveSame) return;

        // Only emit if this spawn is still what's shown on the overlay
        if (overlayLastSpawn && overlayLastSpawn.id === spawn.id) {
          overlayBroadcast({ type: "despawn", spawnId: spawn.id });
          overlayBroadcast({ type: "clear" });
          overlayLastSpawn = null;
        }
      } catch {}
    }, ms + 50);
  } catch {}

  try {
    await refreshKickTokenIfNeeded();
    const res = await sendKickChatMessage(msg);
    if (!res?.ok) console.log("send message failed:", res);
  } catch (e) {
    console.error("announceSpawn failed:", e?.message || e);
  }
}

async function spawnLoop() {
  // Ensure a spawn exists at boot (optional). If you want *no* immediate spawn,
  // set SPAWN_ON_BOOT=0.
  const spawnOnBoot = String(process.env.SPAWN_ON_BOOT || "1") !== "0";
  if (spawnOnBoot) {
    const spawn = await game.ensureSpawnExists();
    await announceSpawn(spawn);
  }

  // Randomized spawn interval (min/max)
  // Defaults: 60s - 900s (1m - 15m)
  const minS = envInt("SPAWN_DELAY_MIN_SECONDS", 60);
  const maxS = envInt("SPAWN_DELAY_MAX_SECONDS", 900);
  const nextDelayMs = () => {
    const min = Math.max(5, minS);
    const max = Math.max(min, maxS);
    const secs = min + Math.floor(Math.random() * (max - min + 1));
    return secs * 1000;
  };

  let timer = null;
  const schedule = () => {
    if (timer) clearTimeout(timer);
    const delay = nextDelayMs();
    console.log(`[spawn] next spawn in ${Math.round(delay / 1000)}s`);
    timer = setTimeout(async () => {
      try {
        const active = await game.getActiveSpawn();
        if (!active) {
          const s = await game.spawn();
          await announceSpawn(s);
        }
      } catch (e) {
        console.error("Spawn loop error:", e);
      } finally {
        schedule();
      }
    }, delay);
  };

  schedule();
}

// ---------- PKCE helpers (REQUIRED by Kick OAuth 2.1) ----------
function base64UrlEncode(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function makeCodeVerifier() {
  return base64UrlEncode(crypto.randomBytes(64));
}

function makeCodeChallenge(verifier) {
  const hash = crypto.createHash("sha256").update(verifier).digest();
  return base64UrlEncode(hash);
}

function makeState() {
  return crypto.randomUUID();
}

function getPublicBaseUrl(req) {
  const fromEnv = process.env.PUBLIC_BASE_URL;
  if (fromEnv) return fromEnv.replace(/\/+$/g, "");
  return `${req.protocol}://${req.get("host")}`.replace(/\/+$/g, "");
}

// ---------- OAuth endpoints for BOT account ----------
app.get("/auth/kick/start", (req, res) => {
  const clientId = process.env.KICK_CLIENT_ID;
  if (!clientId) return res.status(500).send("Missing KICK_CLIENT_ID");

  const ch = normStreamer(req.query.channel || PRIMARY_CHANNEL);
  if (!ch) return res.status(400).send("Missing channel parameter");

  const baseUrl = getPublicBaseUrl(req);
  const redirectUri = `${baseUrl}/auth/kick/callback`;

  const state = makeState();
  const codeVerifier = makeCodeVerifier();
  const codeChallenge = makeCodeChallenge(codeVerifier);

  // Store PKCE verifier + state + channel in a signed, httpOnly cookie
  res.cookie(
    "kick_oauth",
    { state, verifier: codeVerifier, channel: ch, ts: Date.now() },
    {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      signed: true,
      maxAge: 10 * 60 * 1000
    }
  );

  const scope = process.env.KICK_SCOPES || "user:read chat:write";

  const url =
    `https://id.kick.com/oauth/authorize` +
    `?response_type=code` +
    `&client_id=${encodeURIComponent(clientId)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&scope=${encodeURIComponent(scope)}` +
    `&state=${encodeURIComponent(state)}` +
    `&code_challenge=${encodeURIComponent(codeChallenge)}` +
    `&code_challenge_method=S256`;

  return res.redirect(url);
});

app.get("/auth/kick/callback", async (req, res) => {
  try {
    const code = String(req.query.code || "");
    const state = String(req.query.state || "");
    if (!code) return res.status(400).send("Missing code");

    const cookie = req.signedCookies?.kick_oauth;
    const expectedState = cookie?.state;
    const channel = normStreamer(cookie?.channel || PRIMARY_CHANNEL);

    if (!expectedState || expectedState !== state) {
      return res.status(400).send("State mismatch. Retry /auth/kick/start");
    }

    const client_id = process.env.KICK_CLIENT_ID;
    const client_secret = process.env.KICK_CLIENT_SECRET;
    if (!client_id || !client_secret) {
      return res.status(500).send("Missing KICK_CLIENT_ID / KICK_CLIENT_SECRET");
    }

    const code_verifier = cookie?.verifier;
    if (!code_verifier) {
      return res.status(400).send("Missing PKCE verifier. Retry /auth/kick/start");
    }

    const baseUrl = getPublicBaseUrl(req);
    const redirect_uri = `${baseUrl}/auth/kick/callback`;

    const tokenUrl = "https://id.kick.com/oauth/token";
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id,
      client_secret,
      redirect_uri,
      code_verifier,
      code
    });

    const resp = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body
    });

    const text = await resp.text().catch(() => "");
    if (!resp.ok) {
      return res.status(500).send(`Token exchange failed: ${resp.status}
${text}`);
    }

    let data = null;
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }

    const access = data?.access_token;
    const refresh = data?.refresh_token;
    const expiresIn = Number(data?.expires_in || 3600);
    const scope = data?.scope || process.env.KICK_SCOPES || "user:read chat:write";
    const expMs = Date.now() + expiresIn * 1000;

    if (!access || !refresh) return res.status(500).send("Missing tokens in response");

    res.clearCookie("kick_oauth");

    await setKickTokens(channel, {
      accessToken: access,
      refreshToken: refresh,
      expiresAtMs: expMs,
      scope
    });
    await clearNeedsAuth(channel);

    // Kick a refresh pass so the send path is ready
    refreshKickTokenIfNeeded(channel, { force: false }).catch(() => {});

    res.status(200).type("html").send(
      [
        '<!doctype html>',
        '<html><body style="font-family:system-ui;padding:24px">',
        `<h3>✅ Authorized for #${channel}</h3>`,
        '<p>You can close this tab and return to OBS/stream.</p>',
        `<p><a href="/auth/kick">Back to auth status</a></p>`,
        '</body></html>'
      ].join("\n")
    );
  } catch (e) {
    console.error("OAuth callback error:", e);
    res.status(500).send("OAuth callback failed (see server logs).");
  }
});

// ---------- API endpoints ----------
app.get("/state", async (req, res) => {
  try {
    const spawn = await game.getActiveSpawn();
    const lb = await game.leaderboard(10);
    res.json({ spawn, leaderboard: lb });
  } catch (e) {
    console.error("/state error:", e);
    res.status(500).json({ ok: false, error: "internal_error" });
  }
});

// ---------- OBS Overlay ----------
app.get("/overlay", (req, res) => {
  const showUi = String(req.query.ui || "") === "1";
  const html = `<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Pokemon Overlay</title>
  <style>
    html,body{margin:0; padding:0; width:450px; height:450px; background:transparent; overflow:hidden;}
    #wrap{position:relative; width:450px; height:450px;}
    #card{position:absolute; left:50%; top:50%; transform:translate(-50%,-50%); display:none; align-items:center; gap:18px; padding:14px 18px; border-radius:18px; background:rgba(0,0,0,0.55); backdrop-filter:blur(6px); color:white; font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;}
    #sprite{width:160px; height:160px; image-rendering:pixelated;}
    #name{font-size:28px; font-weight:800; line-height:1.1; white-space:nowrap; max-width:240px; overflow:hidden; text-overflow:ellipsis;}
    #meta{opacity:0.9; font-size:18px;}
    .shiny{filter: drop-shadow(0 0 18px rgba(255,255,255,0.9)); animation: shimmer 1.2s ease-in-out infinite;}
    @keyframes shimmer{0%{filter: drop-shadow(0 0 10px rgba(255,255,255,0.45));} 50%{filter: drop-shadow(0 0 24px rgba(255,255,255,0.95));} 100%{filter: drop-shadow(0 0 10px rgba(255,255,255,0.45));}}
    .pop{animation: pop 300ms ease-out;}
    @keyframes pop{from{transform:translate(-50%,-50%) scale(0.85); opacity:0;} to{transform:translate(-50%,-50%) scale(1); opacity:1;}}
    #barWrap{margin-top:10px; width:260px; height:10px; background:rgba(255,255,255,0.20); border-radius:999px; overflow:hidden;}
    #bar{width:100%; height:100%; background:rgba(255,255,255,0.85); transform-origin:left center; transition: transform 220ms linear;}
    #toast{position:absolute; left:50%; top:calc(50% + 125px); transform:translateX(-50%); display:none; padding:10px 14px; border-radius:14px; background:rgba(0,0,0,0.60); color:white; font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif; font-size:20px; white-space:nowrap;}
    #toast.show{display:block; animation: toast 1400ms ease-out both;}
    @keyframes toast{0%{transform:translate(-50%,-6px); opacity:0;} 12%{transform:translate(-50%,0); opacity:1;} 80%{opacity:1;} 100%{transform:translate(-50%,6px); opacity:0;}}

    /* Battle overlay */
    #battle{position:absolute; left:0; top:0; width:450px; height:450px; display:none; color:white; font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;}
    #battle.show{display:block;}
    #battleTop{position:absolute; left:0; top:0; width:450px; height:240px;}
    #battleBottom{position:absolute; left:0; top:190px; width:450px; height:180px;}
    .sprite{image-rendering:pixelated;}
    .foeSprite{position:absolute; right:28px; top:40px; width:140px; height:140px;}
    .userSprite{position:absolute; left:28px; top:20px; width:150px; height:150px;}
    /* Send-out animations (slide-in sprites) */
    .userEnter{animation:userEnter 520ms cubic-bezier(.22,.9,.25,1.05) both;}
    @keyframes userEnter{0%{left:-180px; opacity:0;} 70%{left:40px; opacity:1;} 100%{left:28px; opacity:1;}}
    .foeEnter{animation:foeEnter 520ms cubic-bezier(.22,.9,.25,1.05) both;}
    @keyframes foeEnter{0%{right:-180px; opacity:0;} 70%{right:40px; opacity:1;} 100%{right:28px; opacity:1;}}

    .side{position:absolute; padding:12px 14px; border-radius:16px; background:rgba(0,0,0,0.55); backdrop-filter:blur(6px); min-width:240px;}
    .side.foe{left:22px; top:26px;}
    .side.user{right:22px; top:24px;}
    .label{display:flex; justify-content:space-between; gap:10px; font-weight:800; font-size:18px; white-space:nowrap;}
    .label span{max-width:170px; overflow:hidden; text-overflow:ellipsis;}
    .hpWrap{margin-top:10px; width:100%; height:12px; background:rgba(255,255,255,0.20); border-radius:999px; overflow:hidden;}
    .hp{width:100%; height:100%; background:rgba(255,255,255,0.90); transform-origin:left center; transition: transform 520ms linear;}
    #battleText{position:absolute; left:22px; right:22px; bottom:18px; padding:14px 16px; border-radius:16px; background:rgba(0,0,0,0.65); backdrop-filter:blur(6px); font-size:18px; line-height:1.25; min-height:54px; white-space:pre-line;}
    #battle.flash{animation: battleFlash 180ms ease-out;}
    @keyframes battleFlash{from{transform:scale(0.99); opacity:0.85;} to{transform:scale(1); opacity:1;}}

    /* Damage feedback */
    .shake{animation: shake 260ms ease-in-out;}
    @keyframes shake{
      0%{transform:translate(0,0);} 15%{transform:translate(-6px,0);} 30%{transform:translate(6px,0);} 45%{transform:translate(-5px,0);} 60%{transform:translate(5px,0);} 75%{transform:translate(-3px,0);} 100%{transform:translate(0,0);} 
    }
    .hitFlash{animation: hitFlash 180ms ease-out;}
    @keyframes hitFlash{from{filter:brightness(1.9) contrast(1.05);} to{filter:brightness(1) contrast(1);}}

    /* Attack "lunge" when using a move */
    .attackUser{animation: userAttack 260ms ease-out;}
    @keyframes userAttack{0%{transform:translate(0,0);} 45%{transform:translate(18px,-4px);} 100%{transform:translate(0,0);} }
    .attackFoe{animation: foeAttack 260ms ease-out;}
    @keyframes foeAttack{0%{transform:translate(0,0);} 45%{transform:translate(-18px,4px);} 100%{transform:translate(0,0);} }

    /* Effectiveness / crit popup */
    #popup{position:absolute; left:50%; top:160px; transform:translateX(-50%); display:none; padding:10px 14px; border-radius:14px; background:rgba(0,0,0,0.70); backdrop-filter:blur(6px); font-weight:900; letter-spacing:0.5px; font-size:20px; text-transform:uppercase; white-space:nowrap;}
    #popup.show{display:block; animation: popup 850ms ease-out both;}
    @keyframes popup{0%{transform:translate(-50%,8px) scale(0.92); opacity:0;} 18%{transform:translate(-50%,0) scale(1); opacity:1;} 80%{opacity:1;} 100%{transform:translate(-50%,-6px) scale(1); opacity:0;}}

    /* Small move log */
    #moveLog{position:absolute; left:22px; right:22px; bottom:92px; padding:10px 12px; border-radius:14px; background:rgba(0,0,0,0.45); backdrop-filter:blur(6px); font-size:13px; line-height:1.25; max-height:76px; overflow:hidden;}
    #moveLog .line{opacity:0.95; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;}
    ${showUi ? '#ui{position:absolute; right:16px; bottom:16px; background:rgba(0,0,0,0.5); color:white; padding:12px; border-radius:12px; font-family:system-ui;}' : '#ui{display:none;}'}
  </style>
</head>
<body>
  <div id="wrap">
    <div id="card">
      <img id="sprite"/>
      <div>
        <div id="name"></div>
        <div id="meta"></div>
        <div id="barWrap"><div id="bar"></div></div>
      </div>
    </div>

    <div id="battle">
      <div id="battleTop">
        <div class="side foe">
          <div class="label"><span id="foeName"></span><span id="foeMeta"></span></div>
          <div class="hpWrap"><div id="foeHp" class="hp"></div></div>
        </div>
        <img id="foeSprite" class="sprite foeSprite"/>
      </div>

      <div id="battleBottom">
        <img id="userSprite" class="sprite userSprite"/>
        <div class="side user">
          <div class="label"><span id="userName"></span><span id="userMeta"></span></div>
          <div class="hpWrap"><div id="userHp" class="hp"></div></div>
        </div>
      </div>

      <div id="popup"></div>
      <div id="moveLog"></div>
      <div id="battleText"></div>
    </div>

    <div id="toast"></div>
  </div>

  <script>
    const card = document.getElementById("card");
    const sprite = document.getElementById("sprite");
    const nameEl = document.getElementById("name");
    const metaEl = document.getElementById("meta");
    const bar = document.getElementById("bar");
    const toast = document.getElementById("toast");

    const battleEl = document.getElementById("battle");
    const battleText = document.getElementById("battleText");
    const userSprite = document.getElementById("userSprite");
    const foeSprite = document.getElementById("foeSprite");
    const userName = document.getElementById("userName");
    const userMeta = document.getElementById("userMeta");
    const foeName = document.getElementById("foeName");
    const foeMeta = document.getElementById("foeMeta");
    const userHp = document.getElementById("userHp");
    const foeHp = document.getElementById("foeHp");
    const popup = document.getElementById("popup");
    const moveLog = document.getElementById("moveLog");

    let moveLines = [];

    let battleTimer = null;
    let battleIndex = 0;

    let currentSpawn = null;

    function show(spawn){
      if(!spawn || !spawn.sprite) return;
      currentSpawn = spawn;
      sprite.src = spawn.sprite;
      sprite.className = spawn.isShiny ? "shiny" : "";
      nameEl.textContent = (spawn.isShiny ? "✨ " : "") + spawn.name;
      metaEl.textContent = 'Lv. ' + spawn.level + ' • ' + spawn.tier;
      card.style.display = "flex";
      card.classList.remove("pop"); void card.offsetWidth; card.classList.add("pop");
    }

    function clear(){ currentSpawn=null; card.style.display = "none"; }
    function caught(trainer, pokemon, isShiny){ toast.textContent = '🎮 ' + trainer + ' caught ' + (isShiny ? '✨ ' : '') + pokemon + '!'; toast.classList.remove("show"); void toast.offsetWidth; toast.classList.add("show"); clear(); }
    function despawn(){ clear(); }

    function setHp(el, cur, max){
      try{
        const pct = max ? Math.max(0, Math.min(1, cur / max)) : 1;
        el.style.transform = 'scaleX(' + pct + ')';
      }catch{}
    }

    function stopBattleTimer(){
      if(battleTimer){ clearTimeout(battleTimer); battleTimer=null; }
      battleIndex = 0;
    }

    function hideBattle(){
      stopBattleTimer();
      moveLines = [];
      if(moveLog) moveLog.innerHTML = "";
      if(popup) popup.classList.remove("show");
      if(battleEl){ battleEl.classList.remove("show"); battleEl.style.display="none"; }
    }

    function pulse(el, cls){
      if(!el) return;
      el.classList.remove(cls);
      void el.offsetWidth;
      el.classList.add(cls);
      setTimeout(()=>{ try{ el.classList.remove(cls); }catch{} }, 320);
    }

    function showPopup(text){
      if(!popup || !text) return;
      popup.textContent = text;
      popup.classList.remove("show");
      void popup.offsetWidth;
      popup.classList.add("show");
    }

    // --- Battle SFX ---
    // Disabled for now (no click-to-unlock and no sound effects).
    function playSfx(){ /* disabled */ }

    function pushMoveLine(line){
      if(!moveLog || !line) return;
      moveLines.push(line);
      if(moveLines.length > 5) moveLines = moveLines.slice(moveLines.length - 5);
      moveLog.innerHTML = moveLines.map(l => '<div class="line">' + l.replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</div>').join('');
    }

    function playBattle(b){
      if(!b || !battleEl) return;

      // Hide spawn card while battling
      card.style.display = "none";

      // Fill UI
      if(userSprite) userSprite.src = (b.user && b.user.sprite) || "";
      if(foeSprite) foeSprite.src = (b.foe && b.foe.sprite) || "";
      if(foeSprite && b.foe && b.foe.isShiny) foeSprite.classList.add("shiny"); else if(foeSprite) foeSprite.classList.remove("shiny");

      if(userName) userName.textContent = (b.user && b.user.name) ? b.user.name : "You";
      if(userMeta) userMeta.textContent = b.user && b.user.level ? "Lv. " + b.user.level : "";
      if(foeName) foeName.textContent = (b.foe && b.foe.name) ? b.foe.name : "Wild";
      if(foeMeta) foeMeta.textContent = b.foe && b.foe.level ? "Lv. " + b.foe.level : "";

      const frames = Array.isArray(b.frames) ? b.frames : [];
      // Default HP (start full)
      const uMax = frames[0]?.leftMax || b.user?.maxHP || 100;
      const fMax = frames[0]?.rightMax || b.foe?.maxHP || 100;
      setHp(userHp, frames[0]?.leftHp ?? uMax, uMax);
      setHp(foeHp, frames[0]?.rightHp ?? fMax, fMax);

      battleEl.style.display = "block";
      battleEl.classList.add("show");
      battleEl.classList.remove("flash"); void battleEl.offsetWidth; battleEl.classList.add("flash");

      stopBattleTimer();
      battleIndex = 0;
      moveLines = [];
      if(moveLog) moveLog.innerHTML = "";
      if(popup) popup.classList.remove("show");

function animateEnter(spriteEl, cls){
  if(!spriteEl) return;
  spriteEl.classList.remove(cls);
  void spriteEl.offsetWidth;
  spriteEl.classList.add(cls);
  setTimeout(()=>{ try{ spriteEl.classList.remove(cls); }catch{} }, 700);
}

function renderFrame(i){
  const fr = frames[i];
  if(!fr) return;

  const a = fr.action || null;

  // Text + HP
  if(battleText) battleText.textContent = fr.text || "";

  // Default: render HP from the frame snapshot.
  // Special case: impact frames carry hpFrom/hpTo so we can tick down like mainline Pokémon.
  const isImpact = a && a.kind === 'impact' && (a.hpFrom != null) && (a.hpTo != null);
  if(isImpact){
    // Show pre-hit HP immediately, then tick down shortly after.
    if(a.defender === 'L') setHp(userHp, a.hpFrom, fr.leftMax ?? uMax);
    else setHp(foeHp, a.hpFrom, fr.rightMax ?? fMax);
    // Ensure the other bar still updates correctly.
    if(a.defender === 'L') setHp(foeHp, fr.rightHp ?? fMax, fr.rightMax ?? fMax);
    else setHp(userHp, fr.leftHp ?? uMax, fr.leftMax ?? uMax);

    setTimeout(()=>{
      try{
        if(a.defender === 'L') setHp(userHp, a.hpTo, fr.leftMax ?? uMax);
        else setHp(foeHp, a.hpTo, fr.rightMax ?? fMax);
      }catch{}
    }, 90);
  } else {
    setHp(userHp, fr.leftHp ?? uMax, fr.leftMax ?? uMax);
    setHp(foeHp, fr.rightHp ?? fMax, fr.rightMax ?? fMax);
  }

  // Subtle flash on most frames, but skip on pause frames
  if(!a || a.kind !== 'pause'){
    battleEl.classList.remove("flash"); void battleEl.offsetWidth; battleEl.classList.add("flash");
  }

  // Animation / popups / move log
  if(a){
    const atkName = a.attacker === 'L' ? (b.user?.name || 'You') : (b.foe?.name || 'Wild');
    const defSprite = a.defender === 'L' ? userSprite : foeSprite;

    if(a.kind === 'start'){
      // Wild appears
      animateEnter(foeSprite, 'foeEnter');
    }

    if(a.kind === 'sendout'){
      animateEnter(userSprite, 'userEnter');
    }

    if(a.kind === 'use'){
      // "X used MOVE!" (log only; battleText already shows it)
      pushMoveLine(atkName + ' used ' + (a.moveName || 'a move') + '!');

      // Attacker "lunge" animation like Pokémon (brief forward jab)
      const atkSprite = a.attacker === 'L' ? userSprite : foeSprite;
      pulse(atkSprite, a.attacker === 'L' ? 'attackUser' : 'attackFoe');
    }

    if(a.kind === 'attack'){
      // Pure animation beat (keeps the same text on-screen)
      const atkSprite = a.attacker === 'L' ? userSprite : foeSprite;
      pulse(atkSprite, a.attacker === 'L' ? 'attackUser' : 'attackFoe');
      // Extra little motion so it's obvious a move is being performed
      pulse(atkSprite, 'shake');
    }

    if(a.kind === 'impact'){
      // Impact beat: defender shakes/flashes while HP ticks down.
      pulse(defSprite, 'shake');
      pulse(defSprite, 'hitFlash');

      // Hit SFX
      playSfx('hit');
      if(a.crit) playSfx('crit');
      if(a.mult >= 2) playSfx('super');

      // Add a compact summary to the move log (damage + tags)
      const dmg = (a.damage != null) ? (' -' + a.damage) : '';
      let effTag = '';
      if(a.mult >= 4) effTag = ' (SUPER!)';
      else if(a.mult === 2) effTag = ' (SUPER)';
      else if(a.mult > 0 && a.mult <= 0.5) effTag = ' (RESIST)';
      const critTag = a.crit ? ' (CRIT)' : '';
      if(dmg) pushMoveLine('↳' + dmg + effTag + critTag);
    }

    if(a.kind === 'hit'){
      // These are "text beats" after the impact. We avoid re-shaking here so it feels like Pokémon.
      // Still show popups for crit/effectiveness.
      if(a.mult >= 2) showPopup('SUPER EFFECTIVE!');
      else if(a.mult > 0 && a.mult <= 0.5) showPopup('NOT VERY EFFECTIVE…');
      else if(a.crit) showPopup('CRITICAL HIT!');
    }

    if(a.kind === 'status_inflict'){
      // Status applied message (text already shows). Add a quick popup + log.
      const st = String(a.status || '').toLowerCase();
      if(st === 'burn') showPopup('BURNED!');
      else if(st === 'poison') showPopup('POISONED!');
      pushMoveLine('↳ ' + (st ? st.toUpperCase() : 'STATUS'));
      playSfx('status');
    }

    if(a.kind === 'status_tick'){
      // DOT tick (text already shows)
      playSfx('status');
    }

    if(a.kind === 'faint'){
      playSfx('faint');
    }

    if(a.kind === 'miss'){
      pushMoveLine('↳ MISS!');
      showPopup('MISS!');
    }

    if(a.kind === 'noeffect'){
      pushMoveLine('↳ NO EFFECT');
      showPopup('NO EFFECT!');
    }

  }
}

// Play frames with per-frame duration (default 1s).
function scheduleNext(){
  if(battleIndex >= frames.length){
    stopBattleTimer();
    setTimeout(()=>{ hideBattle(); }, 650);
    return;
  }
  renderFrame(battleIndex);
  const fr = frames[battleIndex];
  const ms = Math.max(200, Number(fr?.durationMs || 1000));
  // Tiny gap only (OBS timers can feel "sped up" if we add extra padding per frame).
  const gap = 60;
  battleIndex++;
  battleTimer = setTimeout(scheduleNext, ms + gap);
}

stopBattleTimer();
battleIndex = 0;
scheduleNext();
    }


    function tickBar(){
      try{
        if(!currentSpawn || !currentSpawn.spawnedAt || !currentSpawn.expiresAt){ requestAnimationFrame(tickBar); return; }
        const start = new Date(currentSpawn.spawnedAt).getTime();
        const end = new Date(currentSpawn.expiresAt).getTime();
        const now = Date.now();
        const pct = Math.max(0, Math.min(1, (end-now)/(end-start)));
        bar.style.transform = 'scaleX(' + pct + ')';
        requestAnimationFrame(tickBar);
      }catch(e){ requestAnimationFrame(tickBar); }
    }
    tickBar();

    // Sound is disabled for now.

    // --- Overlay event transport ---
    // Prefer WebSocket, but fall back to polling (some OBS environments block WS upgrades).
    let lastId = 0;
    let pollTimer = null;

    function handleOverlayMsg(msg){
      try{
        if(msg && msg._id) lastId = Math.max(lastId, Number(msg._id) || 0);
        if(msg.type === "spawn") { hideBattle(); show(msg.spawn); }
        if(msg.type === "battle" && msg.battle) playBattle(msg.battle);
        if(msg.type === "clear") { hideBattle(); clear(); }
        if(msg.type === "despawn") { hideBattle(); despawn(); }
        if(msg.type === "caught") caught(msg.trainer || "Someone", msg.pokemon || "a Pokémon", !!msg.isShiny);
        // sound_settings intentionally ignored (sound disabled)
      }catch{}
    }

    async function poll(){
      try{
        const r = await fetch('/overlay/poll?since=' + encodeURIComponent(String(lastId)));
        const j = await r.json();
        const evs = Array.isArray(j?.events) ? j.events : [];
        for(const ev of evs) handleOverlayMsg(ev);
      }catch{}
    }

    function startPolling(){
      if(pollTimer) return;
      poll();
      pollTimer = setInterval(poll, 500);
    }

    function stopPolling(){
      if(pollTimer){ clearInterval(pollTimer); pollTimer = null; }
    }

    try{
      const proto = location.protocol === "https:" ? "wss" : "ws";
      const ws = new WebSocket(proto + '://' + location.host + '/overlay/ws');
      ws.onopen = ()=>{ stopPolling(); };
      ws.onmessage = (e)=>{
        try{ handleOverlayMsg(JSON.parse(e.data)); }catch{}
      };
      ws.onerror = ()=>{ startPolling(); };
      ws.onclose = ()=>{ startPolling(); };
      // If WS doesn't connect quickly, start polling anyway.
      setTimeout(()=>{ try{ if(ws.readyState !== 1) startPolling(); }catch{} }, 1200);
    }catch{
      startPolling();
    }
  </script>
</body>
</html>`;

  res.status(200).type("html").send(html);
});

app.post("/admin/spawn", async (req, res) => {
  const key = req.headers["x-admin-key"];
  if (!process.env.ADMIN_KEY || key !== process.env.ADMIN_KEY) {
    return res.status(401).json({ ok: false, error: "unauthorized" });
  }

  try {
    const s = await game.spawn();
    await announceSpawn(s);
    res.json({ ok: true, spawn: s });
  } catch (e) {
    console.error("/admin/spawn error:", e);
    res.status(500).json({ ok: false, error: "internal_error" });
  }
});

// ---------- Kick chat command handler ----------
// Per-user anti-spam cooldown for ALL bot commands.
// Any command puts that user on cooldown for any other command.
// Default: 2 seconds.
const COMMAND_COOLDOWN_MS = envInt("COMMAND_COOLDOWN_MS", 2000);
const lastCommandAt = new Map();

async function handleChat({ username, userId, content }) {
  const msg = String(content || "").trim();
  if (!msg.startsWith(PREFIX)) return;

  // Global per-user command cooldown (anti-spam)
  const cdKey = userId ? `kick:${String(userId)}` : `kick:${String(username || "").toLowerCase()}`;
  const now = Date.now();
  const last = lastCommandAt.get(cdKey) || 0;
  if (now - last < COMMAND_COOLDOWN_MS) return;
  lastCommandAt.set(cdKey, now);

  const lower = msg.toLowerCase();
  // !catch  (optional: !catch <name>)
  if (lower === `${PREFIX}catch` || lower.startsWith(`${PREFIX}catch `)) {
    const guess = lower === `${PREFIX}catch` ? "" : msg.slice(`${PREFIX}catch `.length);
    const result = await game.tryCatch({
      username,
      platformUserId: userId,
      guessName: guess
    });

    if (!result.ok) {
      // Wrong name: stay silent to avoid chat spam
      if (result.reason === "wrong_name") return;

      if (result.reason === "no_spawn") {
        try {
          await refreshKickTokenIfNeeded();
          await sendKickChatMessage("No Pokémon active right now.");
        } catch {}
        return;
      }

      if (result.reason === "already_caught") return;

      // Catch failed (broke free)
      if (result.reason === "catch_failed") {
        const pct = typeof result.chance === "number" ? Math.round(result.chance * 100) : null;
        try {
          await refreshKickTokenIfNeeded();
          await sendKickChatMessage(
            pct
              ? `${username} almost had it… it broke free! (${pct}% catch chance)`
              : `${username} almost had it… it broke free!`
          );
        } catch {}
        return;
      }

      return;
    }

    const s = result.spawn;
    const shinyTag = s.isShiny ? " ✨SHINY✨" : "";
    const lvlTag = s.level ? `Lv. ${s.level} ` : "";

    try {
      await refreshKickTokenIfNeeded();
      await sendKickChatMessage(
        `${username} caught ${lvlTag}${s.pokemon}${shinyTag} for ${result.catch.pointsEarned} pts!`
      );
    } catch (e) {
      console.error("sendKickChatMessage failed:", e?.message || e);
    }

    // Notify overlay: stop looping sound + show catch animation
    try {
      overlayBroadcast({
        type: "caught",
        spawnId: s.id,
        trainer: username,
        pokemon: s.pokemon,
        isShiny: !!s.isShiny,
        sprite: spriteUrlForSpawn(s)
      });
      overlayBroadcast({ type: "clear" });
      overlayLastSpawn = null;
    } catch {}

    return;
  }

  // !top (leaderboard)
  if (lower === `${PREFIX}top` || lower === `${PREFIX}lb` || lower === `${PREFIX}leaderboard`) {
    const lb = await game.leaderboard(10);
    if (!lb.length) {
      try {
        await refreshKickTokenIfNeeded();
        await sendKickChatMessage("No points yet.");
      } catch {}
      return;
    }
    const line = lb.map((r) => `${r.rank}. ${r.name}: ${r.points}`).join(" | ");
    try {
      await refreshKickTokenIfNeeded();
      await sendKickChatMessage(`🏆 Points Leaderboard — ${line}`);
    } catch (e) {
      console.error("sendKickChatMessage failed:", e?.message || e);
    }

    return;
  }

  // !pokelb (Pokémon catches leaderboard)
  if (lower === `${PREFIX}pokelb` || lower === `${PREFIX}pokemonlb`) {
    const rows = await prisma.catch.groupBy({
      by: ["userId"],
      _count: { _all: true },
      orderBy: { _count: { _all: "desc" } },
      take: 10
    });
    if (!rows.length) {
      try {
        await refreshKickTokenIfNeeded();
        await sendKickChatMessage("No catches yet.");
      } catch {}
      return;
    }
    const users = await prisma.user.findMany({ where: { id: { in: rows.map(r => r.userId) } } });
    const uMap = new Map(users.map(u => [u.id, u]));
    const line = rows
      .map((r, i) => `${i + 1}. ${(uMap.get(r.userId)?.displayName || "unknown")}: ${r._count._all}`)
      .join(" | ");
    try {
      await refreshKickTokenIfNeeded();
      await sendKickChatMessage(`📦 Catch Leaderboard — ${line}`);
    } catch {}
    return;
  }

  // !me
  if (lower === `${PREFIX}me`) {
    const stats = await game.userStats(username);
    if (!stats) {
      try {
        await refreshKickTokenIfNeeded();
        await sendKickChatMessage(`${username}: no stats yet. Catch something!`);
      } catch {}
      return;
    }
    try {
      await refreshKickTokenIfNeeded();
      await sendKickChatMessage(
        `${stats.name} — ${stats.points} pts | ${stats.catches} catches | ✨${stats.shinies}`
      );
    } catch (e) {
      console.error("sendKickChatMessage failed:", e?.message || e);
    }
    return;
  }

  // !inventory (recent catches)  /  !inv
  if (lower === `${PREFIX}inventory` || lower === `${PREFIX}inv`) {
    const user = await game.getOrCreateKickUser(username, userId);
    const leaderPts = await getLeaderPoints(user.id);
    const recent = await prisma.catch.findMany({
      where: { userId: user.id },
      orderBy: { caughtAt: "desc" },
      take: 8
    });
    if (!recent.length) {
      try {
        await refreshKickTokenIfNeeded();
        await sendKickChatMessage(`${username} — no catches yet. LeaderPts: ${leaderPts}`);
      } catch {}
      return;
    }
    const list = recent
      .map((c) => `${c.isShiny ? "✨" : ""}${c.pokemon}${c.level ? " Lv." + c.level : ""}`)
      .join(", ");
    try {
      await refreshKickTokenIfNeeded();
      await sendKickChatMessage(`🎒 ${username} — LeaderPts: ${leaderPts} | Recent: ${list}`);
    } catch {}
    return;
  }

  // !use <pokemon>  (sets your active battle Pokémon; picks your highest level of that species)
  if (lower === `${PREFIX}use` || lower.startsWith(`${PREFIX}use `) || lower === `${PREFIX}pick` || lower.startsWith(`${PREFIX}pick `)) {
    const arg = msg.split(/\s+/).slice(1).join(" ").trim();
    const user = await game.getOrCreateKickUser(username, userId);
    if (!arg) {
      await game.setActivePokemon(user.id, "");
      try { await refreshKickTokenIfNeeded(); await sendKickChatMessage(`${username} — active battle Pokémon cleared. I'll use your highest level catch by default.`); } catch {}
      return;
    }

    // Verify they actually own it (at least one catch)
    const owned = await prisma.catch.findFirst({ where: { userId: user.id, pokemon: { equals: arg, mode: "insensitive" } } });
    if (!owned) {
      try { await refreshKickTokenIfNeeded(); await sendKickChatMessage(`${username} — you don't have a ${arg} yet. Catch one first!`); } catch {}
      return;
    }

    await game.setActivePokemon(user.id, arg);
    try { await refreshKickTokenIfNeeded(); await sendKickChatMessage(`${username} — set active battle Pokémon to ${owned.pokemon}${owned.level ? ` (best Lv.${owned.level})` : ""}.`); } catch {}
    return;
  }

  // !battle  (fight the current spawn with your selected Pokémon; 1v1 for now)
  if (lower === `${PREFIX}battle` || lower === `${PREFIX}fight`) {
    const result = await game.battleActiveSpawn({ username, platformUserId: userId });

    if (!result.ok) {
      if (result.reason === "no_spawn") {
        try { await refreshKickTokenIfNeeded(); await sendKickChatMessage("No Pokémon active right now."); } catch {}
        return;
      }
      if (result.reason === "no_team") {
        try { await refreshKickTokenIfNeeded(); await sendKickChatMessage(`${username} — you have no caught Pokémon to battle with yet. Catch something first!`); } catch {}
        return;
      }
      if (result.reason === "already_caught") return;
      return;
    }

    const s = result.spawn;
    const shinyTag = s.isShiny ? " ✨SHINY✨" : "";
    const lvlTag = s.level ? `Lv. ${s.level} ` : "";

    // Notify overlay: play battle animation.
    try {
      const framesAll = (result.events || result.simEvents || result.frames || []);
      const frames = framesAll.slice(0, 140); // cap to keep overlay snappy
      overlayBroadcast({
        type: "battle",
        battle: {
          trainer: username,
          user: {
            name: result.userMon?.name || "Your Pokémon",
            level: result.userMon?.level || undefined,
            sprite: spriteUrlForName(result.userMon?.name),
            hp: result.userMon?.maxHP ? result.userMon?.hp : undefined,
            maxHP: result.userMon?.maxHP
          },
          foe: {
            name: s.pokemon,
            level: s.level || 5,
            sprite: spriteUrlForSpawn(s),
            isShiny: !!s.isShiny,
            tier: s.tier
          },
          frames
        }
      });
    } catch {}

    // --- Turn-by-turn chat playback (so chat matches overlay pacing) ---
    // We keep this concise to avoid flooding chat: up to 6 turn lines + final.
    const evs = Array.isArray(result.events) ? result.events : [];
    const turnLines = evs
  .filter(e => {
    const k = e?.action?.kind;
    return !!k && ["start","sendout","use","miss","noeffect","faint","status_inflict","status_tick"].includes(k);
  })
  .map(e => String(e.text || "").trim())
  .filter(Boolean)
  .slice(0, 7); // keep it concise

    const battleMs = Math.min(15000, Math.max(2500, frames.reduce((acc,f)=>acc + (Number(f?.durationMs)||1000), 0) + 600));

    try {
      await refreshKickTokenIfNeeded();
      await sendKickChatMessage(`⚔️ ${username} sent out ${result.userMon.name} vs ${lvlTag}${s.pokemon}${shinyTag}!`.trim());
    } catch {}

    // Playback 1 line per second (skip the first event line if it's redundant)
    const playback = turnLines.slice(0, 6);
    for (let i = 0; i < playback.length; i++) {
      setTimeout(async () => {
        try { await sendKickChatMessage(playback[i]); } catch {}
      }, 1000 * (i + 1));
    }

    // Final result at the end
    setTimeout(async () => {
      try {
        if (result.result === 'lost') {
          await sendKickChatMessage(`💥 ${username}'s ${result.userMon.name} lost to ${lvlTag}${s.pokemon}${shinyTag}.`.trim());
        } else {
          await sendKickChatMessage(`🏁 ${username}'s ${result.userMon.name} defeated ${lvlTag}${s.pokemon}${shinyTag}! Caught for ${result.catch.pointsEarned} pts.`.trim());
        }
      } catch {}
    }, battleMs);

    // If the user won, delay the caught flash until after the battle animation
    setTimeout(() => {
      try {
        if (result.result === "won") {
          overlayBroadcast({
            type: "caught",
            spawnId: s.id,
            trainer: username,
            pokemon: s.pokemon,
            isShiny: !!s.isShiny,
            sprite: spriteUrlForSpawn(s)
          });
          overlayBroadcast({ type: "clear" });
          overlayLastSpawn = null;
        } else {
          overlayBroadcast(overlayEventFromSpawn(overlayLastSpawn));
        }
      } catch {}
    }, battleMs);

    return;
  }

  // ---- Trainer vs Trainer battles ----
  // !duel <username>   (challenge another chatter)
  // !accept            (accept a pending duel)
  // !decline           (decline a pending duel)
  if (lower.startsWith(`${PREFIX}duel`) || lower.startsWith(`${PREFIX}pvp`) || lower.startsWith(`${PREFIX}challenge`)) {
    const target = msg.split(/\s+/).slice(1).join(" ").trim();
    if (!target) {
      try { await refreshKickTokenIfNeeded(); await sendKickChatMessage(`Usage: ${PREFIX}duel <username>`); } catch {}
      return;
    }
    const targetHandle = String(target).replace(/^@/, "").trim().toLowerCase();
    const selfHandle = String(username || "").trim().toLowerCase();
    if (!targetHandle || targetHandle === selfHandle) {
      try { await refreshKickTokenIfNeeded(); await sendKickChatMessage(`${username} — choose another user to duel.`); } catch {}
      return;
    }

    // Ensure the target exists in our DB (has chatted before)
    const targetIdent = await prisma.userIdentity.findUnique({ where: { platform_handle: { platform: "kick", handle: targetHandle } } }).catch(() => null);
    if (!targetIdent) {
      try { await refreshKickTokenIfNeeded(); await sendKickChatMessage(`${username} — I don't see @${targetHandle} yet. They need to chat once first.`); } catch {}
      return;
    }

    duelRequests.set(targetHandle, {
      challengerHandle: selfHandle,
      challengerName: username,
      challengerPlatformUserId: userId,
      createdAt: Date.now()
    });
    try { await refreshKickTokenIfNeeded(); await sendKickChatMessage(`⚔️ @${targetHandle}, ${username} challenged you to a duel! Type ${PREFIX}accept to fight (60s).`); } catch {}
    return;
  }

  if (lower === `${PREFIX}decline`) {
    const selfHandle = String(username || "").trim().toLowerCase();
    const req = duelRequests.get(selfHandle);
    if (req) duelRequests.delete(selfHandle);
    try { await refreshKickTokenIfNeeded(); await sendKickChatMessage(`${username} declined the duel.`); } catch {}
    return;
  }

  if (lower === `${PREFIX}accept`) {
    const selfHandle = String(username || "").trim().toLowerCase();
    const req = duelRequests.get(selfHandle);
    if (!req) {
      try { await refreshKickTokenIfNeeded(); await sendKickChatMessage(`${username} — no duel request found. Ask someone to ${PREFIX}duel you.`); } catch {}
      return;
    }
    if (Date.now() - req.createdAt > DUEL_TTL_MS) {
      duelRequests.delete(selfHandle);
      try { await refreshKickTokenIfNeeded(); await sendKickChatMessage(`That duel request expired.`); } catch {}
      return;
    }
    duelRequests.delete(selfHandle);

    // Resolve users
    const challengerUser = await game.getOrCreateKickUser(req.challengerName, req.challengerPlatformUserId);
    const opponentUser = await game.getOrCreateKickUser(username, userId);

    const result = await game.battleTrainers({
      challengerUserId: challengerUser.id,
      challengerName: req.challengerName,
      opponentUserId: opponentUser.id,
      opponentName: username
    });

    if (!result.ok) {
      try { await refreshKickTokenIfNeeded(); await sendKickChatMessage(`Both trainers need at least one caught Pokémon to duel.`); } catch {}
      return;
    }

    // Overlay battle (challenger as "user" side, opponent as "foe" side)
    try {
      const framesAll = (result.events || []);
      const frames = framesAll.slice(0, 140);
      overlayBroadcast({
        type: "battle",
        battle: {
          trainer: `${req.challengerName} vs ${username}`,
          user: {
            name: result.challengerMon?.name || "Trainer",
            level: result.challengerMon?.level || undefined,
            sprite: spriteUrlForName(result.challengerMon?.name),
            maxHP: result.challengerMon?.maxHP,
            hp: result.challengerMon?.hp
          },
          foe: {
            name: result.opponentMon?.name || "Trainer",
            level: result.opponentMon?.level || undefined,
            sprite: spriteUrlForName(result.opponentMon?.name),
            isShiny: false,
            tier: "trainer"
          },
          frames
        }
      });
    } catch {}

    // Chat pacing: announce and then final result after the overlay duration.
    const frames = Array.isArray(result.events) ? result.events : [];
    const duelMs = Math.min(18000, Math.max(3500, frames.reduce((acc,f)=>acc + (Number(f?.durationMs)||1000), 0) + 600));

    try {
      await refreshKickTokenIfNeeded();
      await sendKickChatMessage(`⚔️ DUEL! ${req.challengerName} (${result.challengerMon.name}) vs ${username} (${result.opponentMon.name})`);
    } catch {}

    setTimeout(async () => {
      try {
        const winner = result.result === "challenger" ? req.challengerName : username;
        await sendKickChatMessage(`🏆 ${winner} wins the duel!`);
      } catch {}
    }, duelMs);

    return;
  }

  // !bet <amount>  (alias: !wager)
  // Instant wager: deduct leaderpoints, then immediately attempt to catch the current spawn.
  if (lower.startsWith(`${PREFIX}bet`) || lower.startsWith(`${PREFIX}wager`)) {
    const parts = msg.trim().split(/\s+/);
    const amt = Math.floor(Number(parts[1] || 0));
    if (!Number.isFinite(amt) || amt <= 0) {
      try { await refreshKickTokenIfNeeded(); await sendKickChatMessage(`Usage: ${PREFIX}bet <amount>`); } catch {}
      return;
    }

    const spawn = await game.getActiveSpawn();
    if (!spawn) {
      try { await refreshKickTokenIfNeeded(); await sendKickChatMessage("No Pokémon active to bet on."); } catch {}
      return;
    }

    const user = await game.getOrCreateKickUser(username, userId);
    const bal = await getLeaderPoints(user.id);
    if (amt > bal) {
      try { await refreshKickTokenIfNeeded(); await sendKickChatMessage(`${username} — not enough LeaderPts. Balance: ${bal}`); } catch {}
      return;
    }

    // Deduct wager upfront
    await addLpAdj(user.id, -amt);

    // Attempt catch (no name required)
    const result = await game.tryCatch({
      username,
      platformUserId: userId,
      guessName: ""
    });

    if (!result.ok) {
      // Refund only if there wasn't an active spawn anymore / race condition.
      if (result.reason === "no_spawn" || result.reason === "already_caught") {
        await addLpAdj(user.id, amt);
        try { await refreshKickTokenIfNeeded(); await sendKickChatMessage(`${username} — too late! Someone else got it. Bet refunded.`); } catch {}
        return;
      }

      if (result.reason === "catch_failed") {
        const pct = typeof result.chance === "number" ? Math.round(result.chance * 100) : null;
        try {
          await refreshKickTokenIfNeeded();
          await sendKickChatMessage(
            pct
              ? `${username} bet ${amt} LeaderPts and it broke free! (lost bet) — (${pct}% catch chance)`
              : `${username} bet ${amt} LeaderPts and it broke free! (lost bet)`
          );
        } catch {}
        return;
      }

      // Other failure: refund
      await addLpAdj(user.id, amt);
      return;
    }

    const s = result.spawn;
    const shinyTag = s.isShiny ? " ✨SHINY✨" : "";
    const lvlTag = s.level ? `Lv. ${s.level} ` : "";

    const mult = payoutMultiplierForSpawn(s);
    const payout = Math.max(0, Math.floor(amt * mult));
    await addLpAdj(user.id, payout);

    try {
      await refreshKickTokenIfNeeded();
      await sendKickChatMessage(
        `${username} bet ${amt} LeaderPts and caught ${lvlTag}${s.pokemon}${shinyTag}! +${payout} LeaderPts payout (x${mult.toFixed(2)}) + ${result.catch.pointsEarned} catch pts.`
      );
    } catch {}

    // Notify overlay
    try {
      overlayBroadcast({
        type: "caught",
        spawnId: s.id,
        trainer: username,
        pokemon: s.pokemon,
        isShiny: !!s.isShiny,
        sprite: spriteUrlForSpawn(s)
      });
      overlayBroadcast({ type: "clear" });
      overlayLastSpawn = null;
    } catch {}

    return;
  }

  // Sound controls are disabled for now.
  if (lower.startsWith(`${PREFIX}sound`)) {
    if (String(username || "").toLowerCase() !== STREAMER_USERNAME) return;
    try { await refreshKickTokenIfNeeded(); await sendKickChatMessage("🔇 Overlay sounds are currently disabled."); } catch {}
    return;
  }

  // !spawn (streamer-only)
  if (lower === `${PREFIX}spawn`) {
    if (String(username || "").toLowerCase() !== STREAMER_USERNAME) return;
    const s = await game.spawn();
    await announceSpawn(s);
    return;
  }
}

// ---------- Start everything ----------
const server = app.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);

  (async () => {
    try {
      ensureDbSchema();
      await prisma.$queryRaw`SELECT 1`;

      await migrateLegacyKickTokens();

      // Wire overlay websockets
      overlayWss = new WebSocket.Server({ noServer: true });
      server.on('upgrade', (req, socket, head) => {
        try {
          const url = req.url || '';
          if (url.startsWith('/overlay/ws')) {
            overlayWss.handleUpgrade(req, socket, head, (ws) => {
              overlayWss.emit('connection', ws, req);
            });
            return;
          }
          socket.destroy();
        } catch {
          try { socket.destroy(); } catch {}
        }
      });
      overlayWss.on('connection', async (ws) => {
        try {
          const spawn = overlayLastSpawn || (await game.getActiveSpawn());
          ws.send(JSON.stringify(overlayEventFromSpawn(spawn)));
          const settings = await getSoundSettings(PRIMARY_CHANNEL);
          ws.send(JSON.stringify({ type: "sound_settings", settings }));
        } catch {
          try { ws.send(JSON.stringify({ type: 'clear' })); } catch {}
        }
      });

      startTokenRefreshLoop();

      if (PRIMARY_CHANNEL) {
        try {
          startKickReader({
            channel: PRIMARY_CHANNEL,
            onChat: handleChat,
            onStatus: (s) => console.log(s),
            onError: (e) => console.error(e)
          });
        } catch (e) {
          console.error('Kick reader failed to start:', e);
        }
      } else {
        console.log('KICK_CHANNEL not set (chat reader disabled).');
      }

      try {
        await spawnLoop();
      } catch (e) {
        console.error('spawnLoop failed:', e);
      }

      READY = true;
      BOOT_ERROR = null;
      console.log('✅ READY');
    } catch (e) {
      BOOT_ERROR = e?.message || e;
      READY = false;
      console.error('❌ Boot failed (server still up for /health):', e);
    }
  })();
});
