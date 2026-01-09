// src/tokenStore.js
// Kick token storage backed by Prisma Setting table, with per-streamer keys and
// optional encryption-at-rest via TOKEN_ENCRYPTION_KEY.

const { prisma } = require("./prisma");
const { encryptString, decryptString } = require("./cryptoUtil");

function normStreamer(slug) {
  return String(slug || "")
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\/kick\.com\//, "")
    .replace(/^\/+/, "")
    .replace(/\/+$/, "");
}

async function getRaw(key) {
  const row = await prisma.setting.findUnique({ where: { key } });
  return row?.value ?? null;
}

async function setRaw(key, value) {
  await prisma.setting.upsert({
    where: { key },
    update: { value },
    create: { key, value }
  });
}

function k(streamer, part) {
  return `kick:${normStreamer(streamer)}:${part}`;
}

async function getKickTokens(streamer) {
  const s = normStreamer(streamer);
  if (!s) return null;

  const encAccess = await getRaw(k(s, "access"));
  const encRefresh = await getRaw(k(s, "refresh"));
  const exp = await getRaw(k(s, "expires_at_ms"));
  const scope = await getRaw(k(s, "scope"));

  return {
    streamer: s,
    accessToken: encAccess ? decryptString(encAccess) : null,
    refreshToken: encRefresh ? decryptString(encRefresh) : null,
    expiresAtMs: exp ? Number(exp) : 0,
    scope: scope || null
  };
}

async function setKickTokens(streamer, { accessToken, refreshToken, expiresAtMs, scope }) {
  const s = normStreamer(streamer);
  if (!s) throw new Error("Missing streamer/channel slug");

  if (accessToken != null) {
    await setRaw(k(s, "access"), encryptString(accessToken));
  }
  if (refreshToken != null) {
    await setRaw(k(s, "refresh"), encryptString(refreshToken));
  }
  if (expiresAtMs != null) {
    await setRaw(k(s, "expires_at_ms"), String(Number(expiresAtMs) || 0));
  }
  if (scope != null) {
    await setRaw(k(s, "scope"), String(scope));
  }

  await setRaw(k(s, "updated_at_ms"), String(Date.now()));
}

async function markNeedsAuth(streamer, reason) {
  const s = normStreamer(streamer);
  if (!s) return;
  await setRaw(k(s, "needs_auth"), "1");
  await setRaw(k(s, "needs_auth_reason"), String(reason || ""));
}

async function clearNeedsAuth(streamer) {
  const s = normStreamer(streamer);
  if (!s) return;
  await setRaw(k(s, "needs_auth"), "0");
  await setRaw(k(s, "needs_auth_reason"), "");
}

async function getNeedsAuth(streamer) {
  const s = normStreamer(streamer);
  if (!s) return { needsAuth: true, reason: "missing_streamer" };
  const flag = await getRaw(k(s, "needs_auth"));
  const reason = await getRaw(k(s, "needs_auth_reason"));
  return { needsAuth: flag === "1", reason: reason || null };
}

module.exports = {
  normStreamer,
  getKickTokens,
  setKickTokens,
  markNeedsAuth,
  clearNeedsAuth,
  getNeedsAuth
};
