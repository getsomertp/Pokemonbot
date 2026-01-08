// src/server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { execSync } = require("child_process");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");

const { prisma } = require("./prisma");
const { Game } = require("./game");
const { envInt } = require("./util");
const { startKickReader } = require("./kickRead");
const { sendKickChatMessage, setSetting, getSetting } = require("./kickSend");

const app = express();
app.set("trust proxy", 1); // IMPORTANT for Railway (correct https in req.protocol)

app.use(cors());
app.use(express.json());
app.use(cookieParser(process.env.COOKIE_SECRET || "dev_cookie_secret"));

const PORT = Number(process.env.PORT || 3000);
const PREFIX = process.env.COMMAND_PREFIX || "!";
const KICK_CHANNEL = process.env.KICK_CHANNEL;
const STREAMER_USERNAME = (process.env.STREAMER_USERNAME || KICK_CHANNEL || "").toLowerCase();

const game = new Game();

// ---- Readiness / health (helps avoid Railway 502 confusion) ----
let READY = false;
let BOOT_ERROR = null;

app.get("/", (req, res) => res.status(200).send("ok"));

// Handy helper page to start Kick OAuth (and avoids multi-line template literal syntax issues)
app.get("/auth/kick", (req, res) => {
  const baseUrl = getPublicBaseUrl(req);
  const startUrl = `${baseUrl}/auth/kick/start`;

  const html = [
    "<!doctype html>",
    "<html>",
    "  <head>",
    "    <meta charset=\"utf-8\" />",
    "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />",
    "    <title>Kick OAuth</title>",
    "    <style>",
    "      body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:40px;}",
    "      a{display:inline-block;padding:12px 16px;border:1px solid #ddd;border-radius:10px;text-decoration:none;}",
    "      code{background:#f6f6f6;padding:2px 6px;border-radius:6px;}",
    "    </style>",
    "  </head>",
    "  <body>",
    "    <h1>Kick OAuth (Bot Account)</h1>",
    "    <p>Click to authorize the bot to post chat messages.</p>",
    `    <p><a href=\"${startUrl}\">Authorize on Kick</a></p>`,
    "    <p>If you are testing locally, set <code>PUBLIC_BASE_URL</code> to your Railway URL.</p>",
    "  </body>",
    "</html>"
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

async function announceSpawn(spawn) {
  const msg = `A wild ${spawnLabel(spawn)} appeared! Type ${PREFIX}catch ${spawn.pokemon}`;

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

  const baseUrl = getPublicBaseUrl(req);
  const redirectUri = `${baseUrl}/auth/kick/callback`;

  const state = makeState();
  const codeVerifier = makeCodeVerifier();
  const codeChallenge = makeCodeChallenge(codeVerifier);

  // Store PKCE verifier + state in a signed, httpOnly cookie (works well on Railway)
  res.cookie(
    "kick_oauth",
    { state, verifier: codeVerifier, ts: Date.now() },
    {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      signed: true,
      maxAge: 10 * 60 * 1000, // 10 minutes
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

    res.clearCookie("kick_oauth");

    await setSetting("kick_access_token", access);
    await setSetting("kick_refresh_token", refresh);
    await setSetting("kick_access_expires_at", String(expMs));
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
app.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);

  (async () => {
    try {
      ensureDbSchema();
      await prisma.$queryRaw`SELECT 1`;

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
