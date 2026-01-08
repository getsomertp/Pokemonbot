const { prisma } = require("./prisma");

const KICK_TOKEN_URL = "https://id.kick.com/oauth/token";
const KICK_CHAT_URL = "https://api.kick.com/public/v1/chat"; // :contentReference[oaicite:5]{index=5}

async function getSetting(key) {
  const row = await prisma.setting.findUnique({ where: { key } });
  return row?.value ?? null;
}

async function setSetting(key, value) {
  await prisma.setting.upsert({
    where: { key },
    update: { value },
    create: { key, value }
  });
}

async function refreshAccessTokenIfNeeded() {
  const accessToken = await getSetting("kick_access_token");
  const refreshToken = await getSetting("kick_refresh_token");
  const expiresAt = await getSetting("kick_access_expires_at"); // epoch ms as string

  if (!refreshToken) return { ok: false, reason: "no_refresh_token" };

  const now = Date.now();
  const expMs = expiresAt ? Number(expiresAt) : 0;

  // refresh if missing or expiring within 60 seconds
  if (!accessToken || !expMs || now > (expMs - 60_000)) {
    const client_id = process.env.KICK_CLIENT_ID;
    const client_secret = process.env.KICK_CLIENT_SECRET;

    if (!client_id || !client_secret) return { ok: false, reason: "missing_client_credentials" };

    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id,
      client_secret
    });

    const resp = await fetch(KICK_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body
    });

    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      return { ok: false, reason: "refresh_failed", status: resp.status, text };
    }

    const data = await resp.json();

    // expected fields for OAuth token responses
    const newAccess = data.access_token;
    const newRefresh = data.refresh_token || refreshToken;
    const expiresIn = Number(data.expires_in || 3600);
    const newExpMs = Date.now() + expiresIn * 1000;

    await setSetting("kick_access_token", newAccess);
    await setSetting("kick_refresh_token", newRefresh);
    await setSetting("kick_access_expires_at", String(newExpMs));

    return { ok: true, accessToken: newAccess };
  }

  return { ok: true, accessToken };
}

async function sendKickChatMessage(content) {
  const tok = await refreshAccessTokenIfNeeded();
  if (!tok.ok) return tok;

  const resp = await fetch(KICK_CHAT_URL, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${tok.accessToken}`,
      "Content-Type": "application/json",
      "Accept": "application/json"
    },
    body: JSON.stringify({
      type: "bot",
      content: String(content).slice(0, 500)
    })
  });

  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    return { ok: false, reason: "send_failed", status: resp.status, text };
  }

  const data = await resp.json().catch(() => null);
  return { ok: true, data };
}

module.exports = {
  getSetting,
  setSetting,
  refreshAccessTokenIfNeeded,
  sendKickChatMessage
};
