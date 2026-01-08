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

// --- Basic health routes (prevents Railway 502 confusion) ---
app.get("/health", (req, res) => res.status(200).json({ ok: true, ts: Date.now() }));
app.get("/", (req, res) => res.status(200).send("ok"));

if (!KICK_CHANNEL) {
  console.error("Missing KICK_CHANNEL in env.");
}

const game = new Game();

// ---------- DB bootstrap (Railway-only friendly) ----------
function ensureDbSchema() {
  try {
    console.log("Running: npx prisma db push");
    execSync("npx prisma db push", { stdio: "inherit" });
    console.log("✅ prisma db push complete");
  } catch (e) {
    console.error("❌ prisma db push failed (check DATABASE_URL / Postgres plugin)");
    throw e;
  }
}

// ---------- Spawns ----------
async function announceSpawn(spawn) {
  const shinyTag = spawn.isShiny ? " ✨SHINY✨" : "";
  const msg = `A wild ${spawn.pokemon} appeared (${spawn.tier})${shinyTag}! Type ${PREFIX}catch ${spawn.pokemon}`;

  try {
    const res = await sendKickChatMessage(msg);
    if (!res?.ok) console.log("send message failed:", res);
  } catch (e) {
    console.error("announceSpawn failed (likely bot not authorized yet):", e?.message || e);
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

  // Scopes needed for bot chat sending
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

    res.send("✅ Bot account authorized! Restart the Railway service to apply.");
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
      if (result.reason === "wrong_name") return; // silent miss
      if (result.reason === "no_spawn") {
        try {
          await sendKickChatMessage(`No Pokémon active right now.`);
        } catch {}
        return;
      }
      if (result.reason === "already_caught") return;
      return;
    }

    const s = result.spawn;
    const shinyTag = s.isShiny ? " ✨SHINY✨" : "";
    try {
      await sendKickChatMessage(
        `${username} caught ${s.pokemon}${shinyTag} for ${result.catch.pointsEarned} pts!`
      );
    } catch (e) {
      console.error("sendKickChatMessage failed:", e?.message || e);
    }
    return;
  }

  // !lb
  if (lower === `${PREFIX}lb` || lower === `${PREFIX}leaderboard`) {
    const lb = await game.leaderboard(10);
    if (!lb.length) {
      try {
        await sendKickChatMessage("No points yet.");
      } catch {}
      return;
    }
    const line = lb.map((r) => `${r.rank}. ${r.name}: ${r.points}`).join(" | ");
    try {
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
        await sendKickChatMessage(`${username}: no stats yet. Catch something!`);
      } catch {}
      return;
    }
    try {
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
app.listen(PORT, async () => {
  console.log(`Server listening on ${PORT}`);

  // DB must work; if it doesn't, exit so Railway restarts
  try {
    ensureDbSchema();
    await prisma.$queryRaw`SELECT 1`;
  } catch (e) {
    console.error("DB bootstrap failed:", e);
    process.exit(1);
  }

  // Start Kick reader (don’t crash the whole server if it fails)
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
  }

  // Start spawns, but don't crash the server if bot auth isn't ready
  try {
    await spawnLoop();
  } catch (e) {
    console.error("spawnLoop failed (likely missing Kick auth tokens):", e);
    console.error("Authorize bot at /auth/kick/start then restart the Railway service.");
  }
});
