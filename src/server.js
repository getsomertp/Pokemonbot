// src/server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { execSync } = require("child_process");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const WebSocket = require("ws");

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

// ---- Readiness / health (helps avoid Railway 502 confusion) ----
let READY = false;
let BOOT_ERROR = null;

// ---- Overlay (OBS Browser Source) ----
let overlayWss = null;
let overlayLastSpawn = null;

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
    if (!overlayWss) return;
    const payload = JSON.stringify(event);
    for (const client of overlayWss.clients) {
      if (client.readyState === 1) client.send(payload);
    }
  } catch {}
}


// ---- Seasons + Economy + Wagers ----
async function getSeasonInfo() {
  const now = new Date();
  const lenDays = envInt("SEASON_LENGTH_DAYS", 30);

  const keyStart = "season_start";
  const keyLabel = "season_label";

  const [sRow, lRow] = await Promise.all([
    prisma.setting.findUnique({ where: { key: keyStart } }).catch(() => null),
    prisma.setting.findUnique({ where: { key: keyLabel } }).catch(() => null)
  ]);

  let start = sRow ? new Date(sRow.value) : null;
  let label = lRow ? Number(lRow.value) : NaN;

  if (!start || Number.isNaN(start.getTime())) {
    // default: first day of current month (UTC)
    start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1, 0, 0, 0));
  }
  if (!Number.isFinite(label)) label = 1;

  const expires = start.getTime() + lenDays * 24 * 60 * 60 * 1000;
  if (now.getTime() >= expires) {
    // rollover
    start = new Date(now.getTime());
    label += 1;
  }

  // Persist
  await prisma.setting.upsert({
    where: { key: keyStart },
    create: { key: keyStart, value: start.toISOString() },
    update: { value: start.toISOString() }
  });
  await prisma.setting.upsert({
    where: { key: keyLabel },
    create: { key: keyLabel, value: String(label) },
    update: { value: String(label) }
  });

  return { start, label, lengthDays: lenDays };
}

async function resetSeasonNow() {
  const now = new Date();
  const keyStart = "season_start";
  const keyLabel = "season_label";
  const lRow = await prisma.setting.findUnique({ where: { key: keyLabel } }).catch(() => null);
  let label = lRow ? Number(lRow.value) : 1;
  if (!Number.isFinite(label)) label = 1;
  label += 1;

  await prisma.setting.upsert({
    where: { key: keyStart },
    create: { key: keyStart, value: now.toISOString() },
    update: { value: now.toISOString() }
  });
  await prisma.setting.upsert({
    where: { key: keyLabel },
    create: { key: keyLabel, value: String(label) },
    update: { value: String(label) }
  });
  return { start: now, label };
}

function wagerKey(channel, spawnId, userId) {
  return `wager:${channel}:${spawnId}:${userId}`;
}
function balanceKey(channel, userId) {
  return `bal:${channel}:${userId}`;
}

const STARTING_BALANCE = envInt("STARTING_BALANCE", 1000);
const WAGER_MIN = envInt("WAGER_MIN", 10);
const WAGER_MAX = envInt("WAGER_MAX", 100000);

async function getBalance(channel, userId) {
  const key = balanceKey(channel, userId);
  const row = await prisma.setting.findUnique({ where: { key } });
  if (!row) {
    await prisma.setting.create({ data: { key, value: String(STARTING_BALANCE) } });
    return STARTING_BALANCE;
  }
  const n = Number(row.value);
  return Number.isFinite(n) ? n : STARTING_BALANCE;
}

async function setBalance(channel, userId, amount) {
  const key = balanceKey(channel, userId);
  await prisma.setting.upsert({
    where: { key },
    create: { key, value: String(amount) },
    update: { value: String(amount) }
  });
  return amount;
}

async function adjustBalance(channel, userId, delta) {
  const cur = await getBalance(channel, userId);
  const next = Math.max(0, cur + delta);
  await setBalance(channel, userId, next);
  return { cur, next };
}

function wagerMultiplier(spawn) {
  const tier = String(spawn?.tier || "common").toLowerCase();
  const base = ({
    common: 1.5,
    uncommon: 2,
    rare: 3,
    epic: 5,
    legendary: 10
  })[tier] || 1.5;

  const shiny = spawn?.isShiny ? 10 : 1;
  return base * shiny;
}

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
  const msg = `A wild ${spawnLabel(spawn)} appeared! Type ${PREFIX}catch ${spawn.pokemon}`;

  // Push to OBS overlay
  overlayLastSpawn = spawn;
  overlayBroadcast(overlayEventFromSpawn(spawn));

  try {
    await refreshKickTokenIfNeeded();
    const res = await sendKickChatMessage(msg);
    if (!res?.ok) console.log("send message failed:", res);
  } catch (e) {
    console.error("announceSpawn failed:", e?.message || e);
  }
}

async function spawnLoop() {
  const spawn = await game.ensureSpawnExists();
  await announceSpawn(spawn);

  const interval = envInt("SPAWN_INTERVAL_SECONDS", 90) * 1000;
  setInterval(async () => {
    try {
      const s = await game.spawn();
      await announceSpawn(s);
    } catch (e) {
      console.error("Spawn loop error:", e);
    }
  }, interval);
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
  const html = [
    "<!doctype html>",
    "<html><head><meta charset='utf-8'/>",
    "<meta name='viewport' content='width=device-width, initial-scale=1'/>",
    "<title>PokeBot Overlay</title>",
    "<style>",
    "  html,body{margin:0;padding:0;background:transparent;overflow:hidden;font-family:system-ui, -apple-system, Segoe UI, Roboto, Arial;}",
    "  #wrap{position:relative;width:100vw;height:100vh;}",
    "  #card{position:absolute;left:50%;top:65%;transform:translate(-50%,-50%);display:none;align-items:center;gap:18px;padding:16px 18px;border-radius:18px;background:rgba(0,0,0,.55);backdrop-filter: blur(6px);}",
    "  #spriteWrap{position:relative;width:180px;height:180px;}",
    "  #sprite{width:180px;height:180px;image-rendering:pixelated;}",
    "  .shinyGlow{filter: drop-shadow(0 0 10px rgba(255,215,0,.95)) drop-shadow(0 0 26px rgba(255,255,255,.55));animation: shimmer 1.1s ease-in-out infinite;}",
    "  @keyframes shimmer{0%,100%{transform:scale(1);}50%{transform:scale(1.04);}}",
    "  #meta{color:#fff;min-width:340px;}",
    "  #name{font-size:28px;font-weight:800;letter-spacing:.3px;}",
    "  #sub{margin-top:4px;opacity:.9;font-size:16px;}",
    "  #barOuter{margin-top:10px;width:360px;height:10px;border-radius:999px;background:rgba(255,255,255,.18);overflow:hidden;}",
    "  #barInner{height:100%;width:100%;background:rgba(255,255,255,.85);transform-origin:left center;}",
    "  #catchToast{position:absolute;left:50%;top:18%;transform:translateX(-50%);display:none;align-items:center;gap:12px;padding:12px 14px;border-radius:14px;background:rgba(0,0,0,.55);backdrop-filter: blur(6px);color:#fff;}",
    "  #ball{width:22px;height:22px;border-radius:50%;border:2px solid rgba(255,255,255,.99);position:relative;}",
    "  #ball:before{content:'';position:absolute;left:0;right:0;top:50%;height:2px;background:rgba(255,255,255,.85);transform:translateY(-50%);}",
    "  #ball:after{content:'';position:absolute;left:50%;top:50%;width:6px;height:6px;border-radius:50%;background:rgba(255,255,255,.9);transform:translate(-50%,-50%);}",
    "  .pop{animation: pop .55s ease-out both;}",
    "  @keyframes pop{0%{opacity:0;transform:translateX(-50%) translateY(-10px) scale(.98);}100%{opacity:1;transform:translateX(-50%) translateY(0) scale(1);}}",
    "  .fade{animation: fade 1.1s ease-in forwards;}",
    "  @keyframes fade{0%{opacity:1;}100%{opacity:0;}}",
    "</style></head><body>",
    "<div id='wrap'>",
    "  <div id='catchToast'><div id='ball'></div><div id='catchText'></div></div>",
    "  <div id='card'>",
    "    <div id='spriteWrap'><img id='sprite' /></div>",
    "    <div id='meta'>",
    "      <div id='name'></div>",
    "      <div id='sub'></div>",
    "      <div id='barOuter'><div id='barInner'></div></div>",
    "    </div>",
    "  </div>",
    "</div>",
    "<audio id='sndSpawn' preload='auto' src='data:audio/wav;base64,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'></audio>",
    "<audio id='sndShiny' preload='auto' src='data:audio/wav;base64,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'></audio>",
    "<script>",
    "  const card = document.getElementById('card');",
    "  const sprite = document.getElementById('sprite');",
    "  const nameEl = document.getElementById('name');",
    "  const subEl = document.getElementById('sub');",
    "  const barInner = document.getElementById('barInner');",
    "  const toast = document.getElementById('catchToast');",
    "  const catchText = document.getElementById('catchText');",
    "  const sndSpawn = document.getElementById('sndSpawn');",
    "  const sndShiny = document.getElementById('sndShiny');",
    "  let despawnTimer = null;",
    "",
    "  function safePlay(a){ try{ a.currentTime = 0; a.play(); }catch(e){} }",
    "",
    "  function clearCard(){",
    "    card.style.display='none';",
    "    sprite.classList.remove('shinyGlow');",
    "    if(despawnTimer) clearInterval(despawnTimer);",
    "    despawnTimer=null;",
    "  }",
    "",
    "  function showSpawn(s){",
    "    if(!s || !s.sprite){ clearCard(); return; }",
    "    card.style.display='flex';",
    "    sprite.src = s.sprite;",
    "    sprite.classList.toggle('shinyGlow', !!s.isShiny);",
    "    nameEl.textContent = (s.isShiny ? '✨ ' : '') + s.name + (s.isShiny ? ' ✨' : '');",
    "    subEl.textContent = `Lv. ${s.level} • ${String(s.tier||'')}`;",
    "    safePlay(sndSpawn);",
    "    if(s.isShiny) safePlay(sndShiny);",
    "",
    "    const expiresAt = s.expiresAt ? Date.parse(s.expiresAt) : null;",
    "    const spawnedAt = s.spawnedAt ? Date.parse(s.spawnedAt) : Date.now();",
    "    const total = expiresAt ? Math.max(1000, expiresAt - spawnedAt) : 45000;",
    "    function tick(){",
    "      const now = Date.now();",
    "      const left = expiresAt ? Math.max(0, expiresAt - now) : 0;",
    "      const pct = expiresAt ? (left / total) : 1;",
    "      barInner.style.transform = `scaleX(${pct})`;",
    "      if(expiresAt && left <= 0){ clearCard(); }",
    "    }",
    "    tick();",
    "    if(despawnTimer) clearInterval(despawnTimer);",
    "    despawnTimer = setInterval(tick, 100);",
    "  }",
    "",
    "  function showCatch(ev){",
    "    toast.style.display='flex';",
    "    toast.classList.remove('fade');",
    "    toast.classList.add('pop');",
    "    catchText.textContent = `${ev.trainer} caught ${ev.pokemon}${ev.isShiny ? ' ✨' : ''}`;",
    "    setTimeout(()=>{ toast.classList.remove('pop'); toast.classList.add('fade'); }, 900);",
    "    setTimeout(()=>{ toast.style.display='none'; toast.classList.remove('fade'); }, 2000);",
    "  }",
    "",
    "  const proto = (location.protocol === 'https:') ? 'wss' : 'ws';",
    "  const ws = new WebSocket(`${proto}://${location.host}/overlay/ws`);",
    "  ws.onmessage = (e)=>{",
    "    try{",
    "      const msg = JSON.parse(e.data);",
    "      if(msg.type === 'spawn') showSpawn(msg.spawn);",
    "      else if(msg.type === 'clear') clearCard();",
    "      else if(msg.type === 'catch') showCatch(msg);",
    "    }catch(err){}",
    "  };",
    "</script>",
    "</body></html>"
  ].join("\n");
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
async function handleChat({ username, userId, content }) {
  const msg = String(content || "").trim();
  if (!msg.startsWith(PREFIX)) return;

  const lower = msg.toLowerCase();


  // !bal
  if (lower === `${PREFIX}bal` || lower === `${PREFIX}balance`) {
    try {
      const user = await game.getOrCreateKickUser(username, userId);
      const ch = PRIMARY_CHANNEL || STREAMER_USERNAME || "default";
      const bal = await getBalance(ch, user.id);
      await refreshKickTokenIfNeeded();
      await sendKickChatMessage(`${username} balance: ${bal} coins`);
    } catch (e) {
      console.error("!bal failed:", e);
    }
    return;
  }

  // !wager <amount>  (wager on YOUR next successful catch of the active spawn)
  if (lower.startsWith(`${PREFIX}wager `) || lower.startsWith(`${PREFIX}bet `)) {
    try {
      const amtStr = msg.split(/\s+/).slice(1).join("").trim();
      const amt = Number(amtStr);
      if (!Number.isFinite(amt) || amt <= 0) return;

      const spawn = await game.getActiveSpawn();
      if (!spawn) {
        await refreshKickTokenIfNeeded();
        await sendKickChatMessage(`No active spawn right now.`);
        return;
      }

      const user = await game.getOrCreateKickUser(username, userId);
      const ch = PRIMARY_CHANNEL || STREAMER_USERNAME || "default";

      const wagerAmt = Math.max(WAGER_MIN, Math.min(WAGER_MAX, Math.floor(amt)));
      const bal = await getBalance(ch, user.id);
      if (bal < wagerAmt) {
        await refreshKickTokenIfNeeded();
        await sendKickChatMessage(`${username} not enough coins. Balance: ${bal}`);
        return;
      }

      // charge now
      await adjustBalance(ch, user.id, -wagerAmt);

      // store wager
      await prisma.setting.upsert({
        where: { key: wagerKey(ch, spawn.id, user.id) },
        create: { key: wagerKey(ch, spawn.id, user.id), value: String(wagerAmt) },
        update: { value: String(wagerAmt) }
      });

      const mult = wagerMultiplier(spawn);
      await refreshKickTokenIfNeeded();
      await sendKickChatMessage(`${username} wagered ${wagerAmt} on ${spawn.pokemon}. Payout x${mult.toFixed(1)} if you catch it!`);
    } catch (e) {
      console.error("!wager failed:", e);
    }
    return;
  }

  // !wagercancel (refund your wager if the spawn is still active)
  if (lower === `${PREFIX}wagercancel` || lower === `${PREFIX}betcancel`) {
    try {
      const spawn = await game.getActiveSpawn();
      if (!spawn) return;
      const user = await game.getOrCreateKickUser(username, userId);
      const ch = PRIMARY_CHANNEL || STREAMER_USERNAME || "default";
      const key = wagerKey(ch, spawn.id, user.id);
      const row = await prisma.setting.findUnique({ where: { key } });
      if (!row) {
        await refreshKickTokenIfNeeded();
        await sendKickChatMessage(`${username} you don't have a wager for this spawn.`);
        return;
      }
      const amt = Math.max(0, Number(row.value) || 0);
      await prisma.setting.delete({ where: { key } }).catch(() => {});
      await adjustBalance(ch, user.id, amt);
      await refreshKickTokenIfNeeded();
      await sendKickChatMessage(`${username} wager cancelled. Refunded ${amt} coins.`);
    } catch (e) {
      console.error("!wagercancel failed:", e);
    }
    return;
  }

  // !season
  if (lower === `${PREFIX}season`) {
    try {
      const info = await getSeasonInfo();
      await refreshKickTokenIfNeeded();
      await sendKickChatMessage(`Season #${info.label} — started ${info.start.toISOString().slice(0,10)} (length ${info.lengthDays}d)`);
    } catch (e) {
      console.error("!season failed:", e);
    }
    return;
  }

  // !topseason
  if (lower === `${PREFIX}topseason` || lower === `${PREFIX}seasonlb`) {
    try {
      const info = await getSeasonInfo();
      const lb = await game.leaderboardSince(info.start, 10);
      const lines = lb.map((r) => `${r.rank}. ${r.name}: ${r.points}`).join(" | ");
      await refreshKickTokenIfNeeded();
      await sendKickChatMessage(lines ? `Season #${info.label} Top: ${lines}` : `No season points yet.`);
    } catch (e) {
      console.error("!topseason failed:", e);
    }
    return;
  }

  // !seasonreset (streamer-only)
  if (lower === `${PREFIX}seasonreset`) {
    try {
      if (String(username || "").toLowerCase() !== STREAMER_USERNAME) return;
      const info = await resetSeasonNow();
      await refreshKickTokenIfNeeded();
      await sendKickChatMessage(`Season reset! Now Season #${info.label} (started ${info.start.toISOString().slice(0,10)}).`);
    } catch (e) {
      console.error("!seasonreset failed:", e);
    }
    return;
  }

  // !catch <name>
  if (lower.startsWith(`${PREFIX}catch `)) {
    const guess = msg.slice(`${PREFIX}catch `.length);
    const result = await game.tryCatch({
      username,
      platformUserId: userId,
      guessName: guess
    });

    if (!result.ok) {
      if (result.reason === "wrong_name") return;

      if (result.reason === "no_spawn") {
        try {
          await refreshKickTokenIfNeeded();
          await sendKickChatMessage("No Pokémon active right now.");
        } catch {}
        return;
      }

      if (result.reason === "already_caught") return;

      // NEW: catch failed (correct name but it broke free)
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
    }    // Overlay: show catch popup + clear sprite
    try {
      overlayBroadcast({
        type: 'catch',
        trainer: String(username || 'trainer'),
        pokemon: s.pokemon,
        isShiny: !!s.isShiny
      });
      overlayBroadcast({ type: 'clear' });
    } catch {}

    // Wager payout (if any)
    try {
      const ch = PRIMARY_CHANNEL || STREAMER_USERNAME || "default";
      const key = wagerKey(ch, s.id, result.user.id);
      const row = await prisma.setting.findUnique({ where: { key } });
      if (row) {
        const wagerAmt = Math.max(0, Number(row.value) || 0);
        await prisma.setting.delete({ where: { key } }).catch(() => {});
        const mult = wagerMultiplier(s);
        const winnings = Math.max(0, Math.floor(wagerAmt * mult));
        await adjustBalance(ch, result.user.id, winnings);
        await refreshKickTokenIfNeeded();
        await sendKickChatMessage(`${username} wager won! +${winnings} coins (x${mult.toFixed(1)})`);
      }
    } catch (e) {
      console.error("wager payout failed:", e?.message || e);
    }

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
