// src/server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { execSync } = require("child_process");

const { prisma } = require("./prisma");
const { Game } = require("./game");
const { envInt } = require("./util");
const { startKickReader } = require("./kickRead");
const { sendKickChatMessage, setSetting, getSetting } = require("./kickSend");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = Number(process.env.PORT || 3000);
const PREFIX = process.env.COMMAND_PREFIX || "!";
const KICK_CHANNEL = process.env.KICK_CHANNEL;
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`;
const STREAMER_USERNAME = (process.env.STREAMER_USERNAME || KICK_CHANNEL || "").toLowerCase();

const game = new Game();

// ---- Readiness / health (prevents Railway 502 confusion) ----
let READY = false;
let BOOT_ERROR = null;

app.get("/health", (req, res) => {
  if (READY) return res.status(200).json({ ok: true, ready: true, ts: Date.now() });
  return res.status(503).json({
    ok: false,
    ready: false,
    ts: Date.now(),
    error: BOOT_ERROR ? String(BOOT_ERROR) : "booting"
  });
});

app.get("/", (req, res) => res.status(200).send("ok"));

process.on("unhandledRejection", (e) => {
  console.error("UNHANDLED REJECTION:", e);
});
process.on("uncaughtException", (e) => {
  console.error("UNCAUGHT EXCEPTION:", e);
});

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
async function announceSpawn(spawn) {
  const shinyTag = spawn.isShiny ? " ✨SHINY✨" : "";
  const msg = `A wild ${spawn.pokemon} appeared (${spawn.tier})${shinyTag}! Type ${PREFIX}catch ${spawn.pokemon}`;

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

// ---------- OAuth endpoints for BOT account ----------
const crypto = global.crypto || require("crypto");
function makeState() {
  return crypto.randomUUID();
}

app.get("/auth/kick/start", async (req, res) => {
  const clientId = process.env.KICK_CLIENT_ID;
  if (!clientId) return res.status(500).send("Missing KICK_CLIENT_ID");

  const state = makeState();
  await setSetting("kick_oauth_state", state);

  const scope = encodeURIComponent("chat:write");
  const redirectUri = encodeURIComponent(`${PUBLIC_BASE_URL}/auth/kick/callback`);

  const url =
    `https://id.kick.com/oauth/authorize` +
    `?response_type=code` +
    `&client_id=${encodeURIComponent(clientId)}` +
    `&redirect_uri=${redirectUri}` +
    `&scope=${scope}` +
    `&state=${encodeURIComponent(state)}`;

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

    const tokenUrl = "https://id.kick.com/oauth/token";
    const redirect_uri = `${PUBLIC_BASE_URL}/auth/kick/callback`;

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id,
      client_secret,
      redirect_uri,
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

    await refreshKickTokenIfNeeded({ force: false });

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
      return;
    }

    const s = result.spawn;
    const shinyTag = s.isShiny ? " ✨SHINY✨" : "";
    try {
      await refreshKickTokenIfNeeded();
      await sendKickChatMessage(
        `${username} caught ${s.pokemon}${shinyTag} for ${result.catch.pointsEarned} pts!`
      );
    } catch (e) {
      console.error("sendKickChatMessage failed:", e?.message || e);
    }
    return;
  }

  if (lower === `${PREFIX}lb` || lower === `${PREFIX}leaderboard`) {
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

  // Start loops AFTER server is listening (prevents 502)
  (async () => {
    try {
      ensureDbSchema();
      await prisma.$queryRaw`SELECT 1`;
      startTokenRefreshLoop();

      if (KICK_CHANNEL) {
        startKickReader({
          channel: KICK_CHANNEL,
          onChat: handleChat,
          onStatus: (s) => console.log(s),
          onError: (e) => console.error(e)
        });
      }

      try {
        await spawnLoop();
      } catch (e) {
        console.error("spawnLoop failed (likely missing Kick auth tokens):", e);
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
