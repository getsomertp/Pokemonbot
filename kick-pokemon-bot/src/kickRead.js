// src/kickRead.js
// Pure WebSocket Kick chat reader (no Playwright).
// Connects to Pusher WS and subscribes to chatrooms.<id>.v2 and channel.<id>.
// Emits chat messages via onChat({ username, userId, content })

const WebSocket = require("ws");

const PUSHER_WS =
  "wss://ws-us2.pusher.com/app/32cbd69e4b950bf97679?protocol=7&client=js&version=8.4.0&flash=false";

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function fetchJson(url) {
  const resp = await fetch(url, {
    headers: {
      "user-agent":
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome Safari",
      accept: "application/json,text/plain,*/*"
    }
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`HTTP ${resp.status} ${resp.statusText} for ${url}\n${text}`);
  }
  return resp.json();
}

async function resolveKickIds(channelSlug) {
  const slug = String(channelSlug || "").trim().toLowerCase();
  if (!slug) throw new Error("Missing channel slug");

  // Public Kick JSON endpoints
  const channelData = await fetchJson(`https://kick.com/api/v2/channels/${slug}`);
  const chatroomData = await fetchJson(`https://kick.com/api/v2/channels/${slug}/chatroom`);

  const channelId = channelData?.id;
  const roomId = chatroomData?.id;

  if (!channelId) throw new Error("Could not resolve channel id from Kick API");
  if (!roomId) throw new Error("Could not resolve chatroom id from Kick API");

  return { slug, channelId, roomId };
}

function safeJsonParse(maybeString) {
  if (typeof maybeString !== "string") return maybeString;
  try {
    return JSON.parse(maybeString);
  } catch {
    return maybeString;
  }
}

function extractChat(payload) {
  // Kick payload shapes can vary. Be defensive.
  const p = payload || {};

  const content =
    p?.content ??
    p?.message?.content ??
    p?.data?.content ??
    p?.message?.data?.content ??
    "";

  const username =
    p?.sender?.username ??
    p?.user?.username ??
    p?.message?.sender?.username ??
    p?.message?.user?.username ??
    p?.data?.sender?.username ??
    p?.data?.user?.username ??
    "";

  const userId =
    p?.sender?.id ??
    p?.user?.id ??
    p?.message?.sender?.id ??
    p?.message?.user?.id ??
    p?.data?.sender?.id ??
    p?.data?.user?.id ??
    "";

  return {
    username: username ? String(username) : "",
    userId: userId ? String(userId) : "",
    content: content ? String(content) : ""
  };
}

function startKickReader({ channel, onChat, onStatus, onError }) {
  let stopped = false;
  let ws = null;

  const status = (s) => onStatus && onStatus(s);
  const error = (e) => onError && onError(e);

  async function connectLoop() {
    let attempt = 0;

    while (!stopped) {
      attempt += 1;

      try {
        status(`Resolving Kick ids for #${channel}...`);
        const { channelId, roomId } = await resolveKickIds(channel);

        status(`Connecting WS (attempt ${attempt})...`);
        ws = new WebSocket(PUSHER_WS);

        const openPromise = new Promise((resolve, reject) => {
          ws.once("open", resolve);
          ws.once("error", reject);
        });

        await openPromise;

        status(`WS connected. Subscribing to chatrooms.${roomId}.v2 + channel.${channelId}`);

        // Subscribe to chatroom and channel events
        ws.send(
          JSON.stringify({
            event: "pusher:subscribe",
            data: { channel: `chatrooms.${roomId}.v2` }
          })
        );
        ws.send(
          JSON.stringify({
            event: "pusher:subscribe",
            data: { channel: `channel.${channelId}` }
          })
        );

        ws.on("message", (buf) => {
          try {
            const msg = safeJsonParse(buf.toString());
            const evt = msg?.event;
            const data = safeJsonParse(msg?.data);

            // Handle pusher ping/pong (some clients use pusher:ping)
            if (evt === "pusher:ping") {
              ws?.send(JSON.stringify({ event: "pusher:pong", data: {} }));
              return;
            }

            if (!evt) return;

            // Kick events usually look like: "App\\Events\\ChatMessageEvent"
            const kind = String(evt).split("\\").pop();

            if (kind === "ChatMessageEvent") {
              const payload = safeJsonParse(data);
              const chat = extractChat(payload);

              if (chat.content && chat.username) {
                onChat &&
                  onChat({
                    username: chat.username,
                    userId: chat.userId,
                    content: chat.content
                  });
              }
            }
          } catch (e) {
            error(e);
          }
        });

        ws.on("close", async () => {
          if (stopped) return;
          status("WS closed. Reconnecting...");
        });

        ws.on("error", (e) => {
          if (stopped) return;
          error(e);
        });

        // Block until WS closes
        await new Promise((resolve) => ws.once("close", resolve));
      } catch (e) {
        error(e);
      }

      if (stopped) break;

      // Backoff
      const delay = Math.min(30_000, 1000 * attempt);
      status(`Reconnect in ${Math.round(delay / 1000)}s...`);
      await sleep(delay);
    }
  }

  connectLoop().catch((e) => error(e));

  return {
    stop() {
      stopped = true;
      try {
        ws?.close();
      } catch {}
    }
  };
}

module.exports = { startKickReader };
