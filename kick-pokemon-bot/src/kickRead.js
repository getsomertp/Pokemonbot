const { KickConnection, Events } = require("kick-live-connector"); // :contentReference[oaicite:2]{index=2}

function startKickReader({ channel, onChat, onStatus = console.log, onError = console.error }) {
  const conn = new KickConnection(channel);

  conn.connect()
    .then((status) => onStatus(`Kick reader connected (roomID=${status.roomID})`))
    .catch((err) => onError("Kick reader connection failed:", err));

  conn.on(Events.ChatMessage, (data) => {
    try {
      const content = data?.content ?? "";
      const username = data?.sender?.username ?? "unknown";
      const userId = data?.sender?.id ?? null;
      const messageId = data?.id ?? null;

      onChat({
        platform: "kick",
        username,
        userId,
        messageId,
        content: String(content)
      });
    } catch (e) {
      onError("Kick ChatMessage handler error:", e);
    }
  });

  conn.on("error", (e) => onError("Kick reader error:", e));
  conn.on("disconnected", () => onStatus("Kick reader disconnected"));

  return conn;
}

module.exports = { startKickReader };
