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
app.set("trust proxy", 1);

app.use(cors());
app.use(express.json());

const PORT = Number(process.env.PORT || 3000);
const PREFIX = process.env.COMMAND_PREFIX || "!";
const KICK_CHANNEL = process.env.KICK_CHANNEL;
const STREAMER_USERNAME = (process.env.STREAMER_USERNAME || KICK_CHANNEL || "").toLowerCase();

const game = new Game();

/* ---------------- Cooldowns ---------------- */
const cooldowns = new Map();
function isOnCooldown({ userId, username, action, cooldownMs }) {
  const key = `${userId || username}:${action}`;
  const now = Date.now();
  const last = cooldowns.get(key) || 0;
  if (now - last < cooldownMs) return true;
  cooldowns.set(key, now);
  return false;
}

/* ---------------- Seasonal Reset ---------------- */
async function maybeRotateSeason() {
  const weekMs = 7 * 24 * 60 * 60 * 1000;
  const startedAtStr = await getSetting("season_started_at");
  const seasonIdStr = await getSetting("season_id");

  const startedAt = startedAtStr ? new Date(startedAtStr) : null;
  const seasonId = Number(seasonIdStr || 1);

  if (!startedAt || Number.isNaN(startedAt.getTime())) {
    await setSetting("season_id", String(seasonId));
    await setSetting("season_started_at", new Date().toISOString());
    return { rotated: false, seasonId };
  }

  if (Date.now() - startedAt.getTime() < weekMs) {
    return { rotated: false, seasonId };
  }

  const newSeason = seasonId + 1;
  await setSetting("season_id", String(newSeason));
  await setSetting("season_started_at", new Date().toISOString());
  return { rotated: true, seasonId: newSeason };
}

/* ---------------- Health ---------------- */
let READY = false;
let BOOT_ERROR = null;

app.get("/", (_, res) => res.send("ok"));
app.get("/health", (_, res) =>
  READY
    ? res.json({ ok: true })
    : res.status(503).json({ ok: false, error: BOOT_ERROR || "booting" })
);

/* ---------------- Overlay API ---------------- */
app.get("/api/spawn", async (_, res) => {
  const s = await game.getActiveSpawn();
  if (!s) return res.json({ active: false });

  res.json({
    active: true,
    pokemon: s.pokemon,
    tier: s.tier,
    isShiny: s.isShiny,
    level: s.level,
    expiresAt: s.expiresAt,
    spriteUrl: spriteUrlForActiveSpawn(s)
  });
});

/* ---------------- Overlay HTML (FIXED) ---------------- */
app.get("/overlay", (_, res) => {
  res.setHeader("content-type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>PokéBot Overlay</title>
<style>
html,body{margin:0;padding:0;background:transparent;overflow:hidden}
#card{display:none;text-align:center;color:white;font-family:Arial,sans-serif}
img{width:256px;height:256px;image-rendering:pixelated}
#name{font-size:26px;font-weight:bold;text-shadow:0 0 8px #000}
#meta{font-size:16px;text-shadow:0 0 8px #000}
</style>
</head>
<body>
<div id="card">
  <img id="sprite">
  <div id="name"></div>
  <div id="meta"></div>
</div>

<script>
const card=document.getElementById("card");
const sprite=document.getElementById("sprite");
const nameEl=document.getElementById("name");
const metaEl=document.getElementById("meta");

function fmt(j){
  let parts=[];
  if(j.tier) parts.push(j.tier.toUpperCase());
  if(j.level) parts.push("Lv. "+j.level);
  if(j.expiresAt){
    let s=Math.max(0,Math.ceil((new Date(j.expiresAt)-Date.now())/1000));
    parts.push("⏳ "+s+"s");
  }
  return parts.join(" • ");
}

async function tick(){
  try{
    const r=await fetch("/api/spawn",{cache:"no-store"});
    const j=await r.json();
    if(!j.active){
      card.style.display="none";
      return;
    }
    card.style.display="block";
    sprite.src=j.spriteUrl;
    nameEl.textContent=(j.isShiny?"✨ ":"")+j.pokemon;
    metaEl.textContent=fmt(j);
  }catch{}
}
setInterval(tick,500);
tick();
</script>
</body>
</html>`);
});

/* ---------------- Sprite URL ---------------- */
function spriteUrlForActiveSpawn(spawn) {
  const name = String(spawn.pokemon).toLowerCase();
  return spawn.isShiny
    ? `https://play.pokemonshowdown.com/sprites/gen5-shiny/${name}.png`
    : `https://play.pokemonshowdown.com/sprites/gen5/${name}.png`;
}

/* ---------------- Startup ---------------- */
app.listen(PORT, async () => {
  try {
    execSync("npx prisma db push", { stdio: "inherit" });

    const r = await maybeRotateSeason();
    if (r.rotated) {
      await sendKickChatMessage(`🔄 Weekly reset! Season ${r.seasonId} begins.`);
    }

    startKickReader({
      channel: KICK_CHANNEL,
      onChat: handleChat
    });

    READY = true;
    console.log("✅ Server READY");
  } catch (e) {
    BOOT_ERROR = e.message;
    console.error("Boot failed:", e);
  }
});

/* ---------------- Chat ---------------- */
async function handleChat({ username, userId, content }) {
  const msg = String(content || "").trim().toLowerCase();

  if (msg === "catch") {
    if (isOnCooldown({ userId, username, action: "catch", cooldownMs: 1500 })) return;
    await game.tryCatch({ username, platformUserId: userId });
    return;
  }

  if (msg === "!pokelb") {
    if (isOnCooldown({ userId, username, action: "pokelb", cooldownMs: 3000 })) return;
    const lb = await game.leaderboard(10);
    const line = lb.map(r => `${r.rank}. ${r.name}: ${r.points}`).join(" | ");
    await sendKickChatMessage(`🏆 Leaderboard — ${line}`);
  }
}
