// src/server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { execSync } = require("child_process");
const crypto = require("crypto");

const { prisma } = require("./prisma");
const { Game } = require("./game");
const { envInt } = require("./util");
const { startKickReader } = require("./kickRead");
const { sendKickChatMessage, setSetting, getSetting } = require("./kickSend");

const app = express();
app.set("trust proxy", 1); // IMPORTANT for Railway (correct https in req.protocol)

app.use(cors());
app.use(express.json());

const PORT = Number(process.env.PORT || 3000);
const PREFIX = process.env.COMMAND_PREFIX || "!";
const KICK_CHANNEL = process.env.KICK_CHANNEL;
const STREAMER_USERNAME = (process.env.STREAMER_USERNAME || KICK_CHANNEL || "").toLowerCase();

const game = new Game();

// ---------- Simple anti-spam cooldowns (in-memory) ----------
// Keyed by `${userId || username}:${action}` -> lastMs
const cooldowns = new Map();
function isOnCooldown({ userId, username, action, cooldownMs }) {
  const key = `${userId || String(username || "").toLowerCase()}:${action}`;
  const now = Date.now();
  const last = cooldowns.get(key) || 0;
  if (now - last < cooldownMs) return true;
  cooldowns.set(key, now);
  return false;
}

// ---------- Seasonal (weekly) rotation ----------
async function maybeRotateSeason() {
  const weekMs = 7 * 24 * 60 * 60 * 1000;
  const startedAtStr = await getSetting("season_started_at");
  const seasonIdStr = await getSetting("season_id");

  const startedAt = startedAtStr ? new Date(startedAtStr) : null;
  const seasonId = Number(seasonIdStr || 1) || 1;

  if (!startedAt || Number.isNaN(startedAt.getTime())) {
    await setSetting("season_id", String(seasonId));
    await setSetting("season_started_at", new Date().toISOString());
    return { rotated: false, seasonId };
  }

  const nowMs = Date.now();
  if (nowMs - startedAt.getTime() < weekMs) return { rotated: false, seasonId };

  const newSeason = seasonId + 1;
  await setSetting("season_id", String(newSeason));
  await setSetting("season_started_at", new Date().toISOString());
  return { rotated: true, seasonId: newSeason };
}

// ---- Readiness / health (helps avoid Railway 502 confusion) ----
let READY = false;
let BOOT_ERROR = null;

app.get("/", (req, res) => res.status(200).send("ok"));

app.get("/health", (req, res) => {
  if (READY) return res.status(200).json({ ok: true, ready: true, ts: Date.now() });
  return res.status(503).json({
    ok: false,
    ready: false,
    ts: Date.now(),
    error: BOOT_ERROR ? String(BOOT_ERROR) : "booting"
  });
});

// ---------- OBS Overlay ----------
app.get("/api/spawn", async (req, res) => {
  try {
    const s = await game.getActiveSpawn();
    if (!s) return res.json({ active: false });
    return res.json({
      active: true,
      pokemon: s.pokemon,
      pokemonId: s.pokemonId,
      tier: s.tier,
      isShiny: s.isShiny,
      level: s.level,
      expiresAt: s.expiresAt,
      spriteUrl: await spriteUrlForActiveSpawn(s)
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

app.get("/overlay", (req, res) => {
  // Transparent browser-source overlay. Polls /api/spawn and shows sprite only when active.
  res.setHeader("content-type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>PokéBot Overlay</title>
    <style>
      html, body { margin:0; padding:0; background: transparent; overflow:hidden; }
      #wrap { width: 100vw; height: 100vh; display:flex; align-items:center; justify-content:center; }
      #card { display:none; align-items:center; justify-content:center; flex-direction:column; gap: 8px; }
      img { image-rendering: pixelated; width: 256px; height: 256px; }
      #text { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; text-align:center; }
      #name { font-size: 28px; font-weight: 900; letter-spacing: 0.5px; text-shadow: 0 2px 10px rgba(0,0,0,0.85); }
      #meta { font-size: 18px; font-weight: 700; opacity: 0.95; text-shadow: 0 2px 10px rgba(0,0,0,0.85); }
    </style>
  </head>
  <body>
    <div id="wrap">
      <div id="card">
        <img id="sprite" alt="pokemon" />
        <div id="text">
          <div id="name"></div>
          <div id="meta"></div>
        </div>
      </div>
    </div>
    <script>
      const card = document.getElementById('card');
      const img = document.getElementById('sprite');
      const nameEl = document.getElementById('name');
      const metaEl = document.getElementById('meta');
      let lastUrl = null;

      function fmtMeta(j) {
        const tier = j.tier ? String(j.tier).toUpperCase() : '';
        const lvl = j.level ? `Lv. ${j.level}` : '';
        let left = '';
        if (j.expiresAt) {
          const ms = new Date(j.expiresAt).getTime() - Date.now();
          const s = Math.max(0, Math.ceil(ms / 1000));
          left = `⏳ ${s}s`;
        }
        return [tier, lvl, left].filter(Boolean).join(' • ');
      }

      async function tick() {
        try {
          const r = await fetch('/api/spawn', { cache: 'no-store' });
          const j = await r.json();
          if (!j.active || !j.spriteUrl) {
            card.style.display = 'none';
            lastUrl = null;
            return;
          }
          card.style.display = 'flex';

          const shiny = j.isShiny ? '✨ ' : '';
          nameEl.textContent = `${shiny}${j.pokemon || ''}`.trim();
          metaEl.textContent = fmtMeta(j);

          if (j.spriteUrl !== lastUrl) {
            img.src = j.spriteUrl;
            lastUrl = j.spriteUrl;
          }
        } catch {}
      }
      setInterval(tick, 500);
      tick();
    </script>
  </body>
</html>`);
});

process.on("unhandledRejection", (e) => console.error("UNHANDLED REJECTION:", e));
process.on("uncaughtException", (e) => console.error("UNCAUGHT EXCEPTION:", e));

// ---------- DB bootstrap ----------
function ensureDbSchema() {
  console.log("Running: npx prisma db push");
  execSync("npx prisma db push", { stdio: "inherit" });
  console.log("✅ prisma db push complete");
}

// ---------- Kick OAuth token auto-refresh ----------
async function refreshKickTokenIfNeeded({ force = false } = {}) {
  try {
    const client_id = process.env.KICK_CLIENT_ID;
    const client_secret = process.env.KICK_CLIENT_SECRET;
    if (!client_id || !client_secret) return;

    const refreshToken = await getSetting("kick_refresh_token");
    if (!refreshToken) return;

    const expStr = await getSetting("kick_access_expires_at");
    const expMs = Number(expStr || 0);

    const now = Date.now();
    const skewMs = 2 * 60 * 1000; // refresh if expiring within 2 min
    const shouldRefresh = force || !expMs || expMs - now <= skewMs;
    if (!shouldRefresh) return;

    console.log("Refreshing Kick access token...");

    const tokenUrl = "https://id.kick.com/oauth/token";
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      client_id,
      client_secret,
      refresh_token: refreshToken
    });

    const resp = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body
    });

    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      console.error(`❌ Kick token refresh failed: ${resp.status} ${resp.statusText}`);
      if (text) console.error(text);
      return;
    }

    const data = await resp.json();

    const access = data.access_token;
    const newRefresh = data.refresh_token || refreshToken;
    const expiresIn = Number(data.expires_in || 3600);
    const newExpMs = Date.now() + expiresIn * 1000;

    if (!access) {
      console.error("❌ Kick token refresh response missing access_token");
      return;
    }

    await setSetting("kick_access_token", access);
    await setSetting("kick_refresh_token", newRefresh);
    await setSetting("kick_access_expires_at", String(newExpMs));

    console.log("✅ Kick access token refreshed");
  } catch (e) {
    console.error("Token refresh error:", e?.message || e);
  }
}

function startTokenRefreshLoop() {
  refreshKickTokenIfNeeded().catch(() => {});
  setInterval(() => refreshKickTokenIfNeeded().catch(() => {}), 60 * 1000);
}

// ---------- Spawns ----------
function spawnLabel(spawn) {
  const levelTag = spawn?.level ? `Lv. ${spawn.level} ` : "";
  const shinyTag = spawn?.isShiny ? " ✨SHINY✨" : "";
  const tierTag = spawn?.tier ? ` (${spawn.tier})` : "";
  return `${levelTag}${spawn.pokemon}${tierTag}${shinyTag}`;
}

function spriteUrlForSpawn(spawn) {
  if (!spawn?.pokemonId) return null;
  // PokeAPI sprite CDN (no auth). pokemonId is Gen 1 string id from dex.
  // Our gen1.dex.json uses string ids like "pikachu" etc; the sprite CDN uses numeric ids.
  // However we also store pokemonId as that string, not the National Dex number.
  // We can still map by looking up dex on demand isn't available here; easiest: use pokemon name -> sprite via pokeapi "pokemon/{name}" isn't ideal.
  // Instead, store numeric spriteId in Spawn later if you want perfect mapping.
  // For now, use the 'pokemon' name (works with the PokeAPI sprites repo via name path is not supported).
  // We'll return a placeholder null and rely on the overlay showing text unless we have a numeric id.
  return null;
}

async function spriteUrlForActiveSpawn(spawn) {
  if (!spawn) return null;
  // We *do* have the string dex id (e.g., "pikachu"). The PokeAPI sprites repo supports name-based endpoints via PokeAPI itself.
  // Use the official PokeAPI sprite endpoint (redirects/serves JSON); but for a direct image we can use the "pokemon" endpoint and read sprites.
  // Since we don't want extra HTTP calls on every overlay poll, we use a stable direct GitHub URL pattern by *name* when possible:
  // https://img.pokemondb.net/sprites/home/normal/{name}.png is another option but could change.
  // Best low-friction: use the Pokemon Showdown sprites by name (stable):
  // https://play.pokemonshowdown.com/sprites/gen5/{name}.png and shiny: .../gen5-shiny/{name}.png
  const name = String(spawn.pokemonId || spawn.pokemon || "").toLowerCase().replace(/[^a-z0-9-]/g, "");
  if (!name) return null;
  return spawn.isShiny
    ? `https://play.pokemonshowdown.com/sprites/gen5-shiny/${name}.png`
    : `https://play.pokemonshowdown.com/sprites/gen5/${name}.png`;
}

async function announceSpawn(spawn) {
  const msg = `A wild ${spawnLabel(spawn)} appeared! Type catch to try and catch it!`;

  try {
    await refreshKickTokenIfNeeded();
    const res = await sendKickChatMessage(msg);
    if (!res?.ok) console.log("send message failed:", res);
  } catch (e) {
    console.error("announceSpawn failed:", e?.message || e);
  }
}

async function announceDespawn(spawn) {
  const msg = `Oh no! ${spawnLabel(spawn)} ran away…`;
  try {
    await refreshKickTokenIfNeeded();
    const res = await sendKickChatMessage(msg);
    if (!res?.ok) console.log("send message failed:", res);
  } catch (e) {
    console.error("announceDespawn failed:", e?.message || e);
  }
}

async function spawnLoop() {
  // If a spawn is already active (e.g., after restart), re-announce it once.
  const existing = await game.getActiveSpawn();
  if (existing) await announceSpawn(existing);

  const minMs = envInt("SPAWN_DELAY_MIN_MS", 1000);
  const maxMs = envInt("SPAWN_DELAY_MAX_MS", 300000);

  const randDelay = () => {
    const lo = Math.max(0, Math.min(minMs, maxMs));
    const hi = Math.max(minMs, maxMs);
    return lo + Math.floor(Math.random() * (hi - lo + 1));
  };

  const tick = async () => {
    try {
      const active = await game.getActiveSpawn();
      if (!active) {
        // If the last spawn expired without being caught, announce it once.
        // This is restart-safe via Spawn.despawnAnnounced.
        const expired = await prisma.spawn.findFirst({
          where: {
            caughtAt: null,
            expiresAt: { lte: new Date() },
            despawnAnnounced: false
          },
          orderBy: { expiresAt: "desc" }
        });

        if (expired) {
          await prisma.spawn.update({
            where: { id: expired.id },
            data: { despawnAnnounced: true }
          });
          await announceDespawn(expired);
        }

        const s = await game.spawn();
        await announceSpawn(s);
      }
    } catch (e) {
      console.error("Spawn loop error:", e);
    } finally {
      setTimeout(tick, randDelay());
    }
  };

  setTimeout(tick, randDelay());
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
app.get("/auth/kick/start", async (req, res) => {
  const clientId = process.env.KICK_CLIENT_ID;
  if (!clientId) return res.status(500).send("Missing KICK_CLIENT_ID");

  const baseUrl = getPublicBaseUrl(req);
  const redirectUri = `${baseUrl}/auth/kick/callback`;

  const state = makeState();
  const codeVerifier = makeCodeVerifier();
  const codeChallenge = makeCodeChallenge(codeVerifier);

  await setSetting("kick_oauth_state", state);
  await setSetting("kick_oauth_code_verifier", codeVerifier);

  const scope = "chat:write";

  const url =
    `https://id.kick.com/oauth/authorize` +
    `?response_type=code` +
    `&client_id=${encodeURIComponent(clientId)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&scope=${encodeURIComponent(scope)}` +
    `&code_challenge=${encodeURIComponent(codeChallenge)}` +
    `&code_challenge_method=S256` +
    `&state=${encodeURIComponent(state)}`;

  console.log("Kick OAuth authorize URL:", url);
  res.redirect(url);
});

app.get("/auth/kick/callback", async (req, res) => {
  try {
    const code = String(req.query.code || "");
    const state = String(req.query.state || "");
    if (!code) return res.status(400).send("Missing code");

    const expectedState = await getSetting("kick_oauth_state");
    if (!expectedState || expectedState !== state) {
      return res.status(400).send("State mismatch. Retry /auth/kick/start");
    }

    const client_id = process.env.KICK_CLIENT_ID;
    const client_secret = process.env.KICK_CLIENT_SECRET;
    if (!client_id || !client_secret) {
      return res.status(500).send("Missing KICK_CLIENT_ID / KICK_CLIENT_SECRET");
    }

    const code_verifier = await getSetting("kick_oauth_code_verifier");
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

    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      return res.status(500).send(`Token exchange failed: ${resp.status}\n${text}`);
    }

    const data = await resp.json();

    const access = data.access_token;
    const refresh = data.refresh_token;
    const expiresIn = Number(data.expires_in || 3600);
    const expMs = Date.now() + expiresIn * 1000;

    if (!access || !refresh) return res.status(500).send("Missing tokens in response");

    await setSetting("kick_access_token", access);
    await setSetting("kick_refresh_token", refresh);
    await setSetting("kick_access_expires_at", String(expMs));

    await setSetting("kick_oauth_state", "");
    await setSetting("kick_oauth_code_verifier", "");

    res.send("✅ Bot account authorized! You can close this tab.");
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
  const lower = msg.toLowerCase();

  // Plain "catch" (no prefix) — only one spawn can be active at a time.
  if (lower === "catch") {
    const cooldownMs = envInt("CATCH_COOLDOWN_MS", 1500);
    if (isOnCooldown({ userId, username, action: "catch", cooldownMs })) return;

    const result = await game.tryCatch({
      username,
      platformUserId: userId,
      // No guessName needed; Game will treat it as "catch active spawn".
      guessName: ""
    });

    if (!result.ok) {
      if (result.reason === "no_spawn") {
        try {
          await refreshKickTokenIfNeeded();
          await sendKickChatMessage("No Pokémon active right now.");
        } catch {}
        return;
      }
      if (result.reason === "already_caught") return;
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
    return;
  }

  // Everything below is prefix commands.
  if (!msg.startsWith(PREFIX)) return;

  // !pokelb (seasonal / weekly)
  if (lower === `${PREFIX}pokelb`) {
    const cooldownMs = envInt("LEADERBOARD_COOLDOWN_MS", 3000);
    if (isOnCooldown({ userId, username, action: "pokelb", cooldownMs })) return;

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
      const seasonId = await getSetting("season_id");
      await sendKickChatMessage(`🏆 Season ${seasonId || 1} Leaderboard — ${line}`);
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
        `${stats.name} — Season ${stats.season}: ${stats.seasonPoints} pts | All-time: ${stats.points} pts | ${stats.catches} catches | ✨${stats.shinies}`
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
app.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);

  (async () => {
    try {
      ensureDbSchema();
      await prisma.$queryRaw`SELECT 1`;

      // Ensure season settings exist + rotate weekly if needed
      try {
        const r = await maybeRotateSeason();
        if (r.rotated) {
          console.log(`🔄 New season started: ${r.seasonId}`);
          try {
            await refreshKickTokenIfNeeded();
            await sendKickChatMessage(`🔄 Weekly reset! Season ${r.seasonId} begins now.`);
          } catch {}
        }
      } catch (e) {
        console.error("maybeRotateSeason failed:", e?.message || e);
      }

      // Check periodically (covers long uptimes)
      setInterval(() => {
        maybeRotateSeason()
          .then(async (r) => {
            if (!r.rotated) return;
            console.log(`🔄 New season started: ${r.seasonId}`);
            try {
              await refreshKickTokenIfNeeded();
              await sendKickChatMessage(`🔄 Weekly reset! Season ${r.seasonId} begins now.`);
            } catch {}
          })
          .catch(() => {});
      }, envInt("SEASON_CHECK_INTERVAL_MS", 5 * 60 * 1000));

      startTokenRefreshLoop();

      if (KICK_CHANNEL) {
        try {
          startKickReader({
            channel: KICK_CHANNEL,
            onChat: handleChat,
            onStatus: (s) => console.log(s),
            onError: (e) => console.error(e)
          });
        } catch (e) {
          console.error("Kick reader failed to start:", e);
        }
      } else {
        console.log("KICK_CHANNEL not set (chat reader disabled).");
      }

      try {
        await spawnLoop();
      } catch (e) {
        console.error("spawnLoop failed:", e);
      }

      READY = true;
      BOOT_ERROR = null;
      console.log("✅ READY");
    } catch (e) {
      BOOT_ERROR = e?.message || e;
      READY = false;
      console.error("❌ Boot failed (server still up for /health):", e);
    }
  })();
});
