// src/cryptoUtil.js
// AES-256-GCM encryption helpers for token-at-rest protection.
//
// TOKEN_ENCRYPTION_KEY must be 32 bytes, base64-encoded.

const crypto = require('crypto');

function getKey() {
  const raw = process.env.TOKEN_ENCRYPTION_KEY;
  if (!raw) return null;
  const key = Buffer.from(raw, 'base64');
  if (key.length !== 32) return null;
  return key;
}

function encryptString(plain) {
  const key = getKey();
  const value = String(plain ?? '');
  if (!key) {
    return JSON.stringify({ encrypted: false, value });
  }

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return JSON.stringify({
    encrypted: true,
    v: 1,
    alg: 'aes-256-gcm',
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ct: ct.toString('base64')
  });
}

function decryptString(stored) {
  if (stored == null) return null;
  const text = String(stored);

  // Try JSON wrapper
  let obj = null;
  try {
    obj = JSON.parse(text);
  } catch {
    obj = null;
  }

  if (obj && obj.encrypted === true && obj.alg === 'aes-256-gcm') {
    const key = getKey();
    if (!key) throw new Error('TOKEN_ENCRYPTION_KEY is required to decrypt stored tokens');

    const iv = Buffer.from(obj.iv, 'base64');
    const tag = Buffer.from(obj.tag, 'base64');
    const ct = Buffer.from(obj.ct, 'base64');

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
    return pt.toString('utf8');
  }

  if (obj && obj.encrypted === false && typeof obj.value === 'string') {
    return obj.value;
  }

  // Plaintext fallback
  return text;
}

module.exports = { encryptString, decryptString };
