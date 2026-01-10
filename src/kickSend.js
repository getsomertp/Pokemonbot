const { getKickTokens, setKickTokens, markNeedsAuth, clearNeedsAuth, normStreamer } = require("./tokenStore");

const KICK_TOKEN_URL = "https://id.kick.com/oauth/token";
const KICK_CHAT_URL = "https://api.kick.com/public/v1/chat";

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function refreshAccessToken({ streamer, force = false } = {}) {
  const s = normStreamer(streamer || process.env.KICK_CHANNEL);
  const tok = await getKickTokens(s);
  if (!tok) return { ok: false, reason: "no_token_row" };

  const now = Date.now();
  const expMs = Number(tok.expiresAtMs || 0);
  const shouldRefresh = force || !tok.accessToken || !expMs || now > (expMs - 120_000);

  if (!shouldRefresh) {
    await clearNeedsAuth(s);
    return { ok: true, accessToken: tok.accessToken, streamer: s };
  }

  if (!tok.refreshToken) {
    await markNeedsAuth(s, "missing_refresh_token");
    return { ok: false, reason: "no_refresh_token" };
  }

  const client_id = process.env.KICK_CLIENT_ID;
  const client_secret = process.env.KICK_CLIENT_SECRET;
  if (!client_id || !client_secret) return { ok: false, reason: "missing_client_credentials" };

  // Retry logic (exponential backoff)
  const maxAttempts = Number(process.env.KICK_REFRESH_MAX_ATTEMPTS || 4);
  let lastErr = null;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      const body = new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: tok.refreshToken,
        client_id,
        client_secret
      });

      const resp = await fetch(KICK_TOKEN_URL, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body
      });

      const text = await resp.text().catch(() => "");
      if (!resp.ok) {
        // 400/401 likely means refresh token is invalid/expired
        if (resp.status === 400 || resp.status === 401) {
          await markNeedsAuth(s, `refresh_rejected_${resp.status}`);
        }
        throw new Error(`refresh_failed_${resp.status}: ${text}`);
      }

      let data = null;
      try {
        data = JSON.parse(text);
      } catch {
        data = null;
      }

      const newAccess = data?.access_token;
      const newRefresh = data?.refresh_token || tok.refreshToken;
      const expiresIn = Number(data?.expires_in || 3600);
      const newExpMs = Date.now() + expiresIn * 1000;
      const scope = data?.scope || tok.scope || null;

      if (!newAccess) {
        throw new Error("refresh_missing_access_token");
      }

      await setKickTokens(s, {
        accessToken: newAccess,
        refreshToken: newRefresh,
        expiresAtMs: newExpMs,
        scope
      });

      await clearNeedsAuth(s);
      return { ok: true, accessToken: newAccess, streamer: s, expiresAtMs: newExpMs };
    } catch (e) {
      lastErr = e;
      const delay = Math.min(30_000, 500 * 2 ** (attempt - 1));
      if (attempt < maxAttempts) await sleep(delay);
    }
  }

  return { ok: false, reason: "refresh_failed", error: String(lastErr?.message || lastErr) };
}

async function sendKickChatMessage(content, streamer) {
  const s = normStreamer(streamer || process.env.KICK_CHANNEL);
  const tok = await refreshAccessToken({ streamer: s, force: false });
  if (!tok.ok) return tok;

  const resp = await fetch(KICK_CHAT_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${tok.accessToken}`,
      "Content-Type": "application/json",
      Accept: "application/json"
    },
    body: JSON.stringify({
      type: "bot",
      content: String(content).slice(0, 500)
    })
  });

  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    // If token became invalid, mark needs auth and surface it
    if (resp.status === 401) {
      await markNeedsAuth(s, "send_unauthorized");
    }
    return { ok: false, reason: "send_failed", status: resp.status, text };
  }

  const data = await resp.json().catch(() => null);
  return { ok: true, data };
}

module.exports = {
  refreshAccessToken,
  sendKickChatMessage
};
