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
    '<!doctype html>',
    '<html>',
    '<head>',
    '<meta charset="utf-8"/>',
    '<meta name="viewport" content="width=device-width, initial-scale=1"/>',
    '<title>Pokemon Overlay</title>',
    '<style>',
    '  body{margin:0; background:transparent; overflow:hidden;}',
    '  #wrap{position:relative; width:100vw; height:100vh;}',
    '  #card{position:absolute; left:40px; top:40px; display:none; align-items:center; gap:18px; padding:14px 18px; border-radius:18px; background:rgba(0,0,0,0.55); backdrop-filter:blur(6px); color:white; font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;}',
    '  #sprite{width:140px; height:140px; image-rendering:pixelated;}',
    '  #name{font-size:28px; font-weight:800; line-height:1.1;}',
    '  #meta{opacity:0.9; font-size:18px;}',
    '  .shiny{filter: drop-shadow(0 0 18px rgba(255,255,255,0.9));}',
    '  .pop{animation: pop 300ms ease-out;}',
    '  @keyframes pop{from{transform:scale(0.85); opacity:0;} to{transform:scale(1); opacity:1;}}',
    '</style>',
    '</head>',
    '<body>',
    '<div id="wrap">',
    '  <div id="card">',
    '    <img id="sprite"/>',
    '    <div>',
    '      <div id="name"></div>',
    '      <div id="meta"></div>',
    '    </div>',
    '  </div>',
    '</div>',
    '<script>',
    '  const card = document.getElementById("card");',
    '  const sprite = document.getElementById("sprite");',
    '  const nameEl = document.getElementById("name");',
    '  const metaEl = document.getElementById("meta");',
    '  let hideT = null;',
    '  function show(spawn){',
    '    if(!spawn || !spawn.sprite) return;',
    '    sprite.src = spawn.sprite;',
    '    sprite.className = spawn.isShiny ? "shiny" : "";',
    '    nameEl.textContent = (spawn.isShiny ? "✨ " : "") + spawn.name;',
    '    metaEl.textContent = `Lv. ${spawn.level} • ${spawn.tier}`;',
    '    card.style.display = "flex";',
    '    card.classList.remove("pop");',
    '    void card.offsetWidth;',
    '    card.classList.add("pop");',
    '    if(hideT) clearTimeout(hideT);',
    '    hideT = setTimeout(()=>{ card.style.display = "none"; }, 15000);',
    '  }',
    '  function clear(){ card.style.display = "none"; }',
    '  const proto = location.protocol === "https:" ? "wss" : "ws";',
    '  const ws = new WebSocket(`${proto}://${location.host}/overlay/ws`);',
    '  ws.onmessage = (e)=>{',
    '    try{',
    '      const msg = JSON.parse(e.data);',
    '      if(msg.type === "spawn") show(msg.spawn);',
    '      if(msg.type === "clear") clear();',
    '    }catch{}',
    '  };',
    '</script>',
    '</body></html>'
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
    }

    // Clear OBS overlay once caught
    
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
