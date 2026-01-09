const fs = require("fs");
const path = require("path");

// Cached dex in-memory (avoid re-reading on every spawn)
let _cache = null;

function envInt(name, fallback) {
  const v = process.env[name];
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) ? n : fallback;
}

/**
 * Loads the generated Gen 1 dex JSON from /data/gen1.dex.json.
 * Shape:
 * { generatedAt, generation, count, pokemon: [ { id, name, dex, types, catchRate, baseStats, learnset, moves } ] }
 */
function loadDex() {
  if (_cache) return _cache;

  const file = path.join(__dirname, "..", "data", "gen1.dex.json");
  const raw = fs.readFileSync(file, "utf8");
  const parsed = JSON.parse(raw);

  // Build quick lookup maps
  const byId = new Map();
  const byName = new Map();
  for (const p of parsed.pokemon || []) {
    byId.set(p.id, p);
    byName.set(String(p.name || "").toLowerCase(), p);
  }

  _cache = { ...parsed, byId, byName };
  return _cache;
}

/**
 * Roll a level for a spawn. Uses LEVEL_MIN / LEVEL_MAX env vars.
 */
function rollLevel(rng = Math.random) {
  const min = envInt("LEVEL_MIN", 3);
  const max = envInt("LEVEL_MAX", 75);
  const lo = Math.min(min, max);
  const hi = Math.max(min, max);
  return lo + Math.floor(rng() * (hi - lo + 1));
}

/**
 * Simple stat formula (no IV/EV/nature):
 * HP: floor(((2*base)*level)/100) + level + 10
 * Others: floor(((2*base)*level)/100) + 5
 */
function computeStats(baseStats, level) {
  const b = baseStats || {};
  const lvl = Math.max(1, Number(level) || 1);

  const hp = Math.floor(((2 * (b.hp || 1)) * lvl) / 100) + lvl + 10;
  const stat = (x) => Math.floor(((2 * (x || 1)) * lvl) / 100) + 5;

  return {
    level: lvl,
    hp,
    atk: stat(b.atk),
    def: stat(b.def),
    spa: stat(b.spa),
    spd: stat(b.spd),
    spe: stat(b.spe),
  };
}

/**
 * Returns up to 4 moves available at `level`.
 * Picks the latest learned moves, unique by moveId.
 */
function getMovesForLevel(pokemon, level) {
  if (!pokemon) return [];
  const lvl = Math.max(1, Number(level) || 1);

  const learnset = Array.isArray(pokemon.learnset) ? pokemon.learnset : [];
  const candidates = learnset
    .filter((m) => (m?.level ?? 0) <= lvl && m?.moveId)
    .sort((a, b) => (a.level ?? 0) - (b.level ?? 0));

  const picked = [];
  const seen = new Set();
  for (let i = candidates.length - 1; i >= 0 && picked.length < 4; i--) {
    const id = candidates[i].moveId;
    if (!id || seen.has(id)) continue;
    seen.add(id);
    picked.push(id);
  }
  picked.reverse();

  const movesDict = pokemon.moves || {};
  return picked
    .map((id) => movesDict[id])
    .filter(Boolean)
    .map((m) => ({
      id: m.id,
      name: m.name,
      power: m.power ?? null,
      accuracy: m.accuracy ?? null,
      pp: m.pp ?? null,
      priority: m.priority ?? 0,
      type: m.type,
      damageClass: m.damageClass,
      meta: m.meta || {},
    }));
}

/**
 * Easy-to-tune catch chance (0..1).
 */
function catchChance({ catchRate, level, tier }) {
  const rate = Math.max(1, Math.min(255, Number(catchRate) || 45));
  const lvl = Math.max(1, Number(level) || 1);

  // 45 -> ~0.28, 255 -> ~0.85 (before modifiers)
  let chance = 0.08 + (rate / 255) * 0.77;

  const tierMult =
    {
      common: 1.0,
      uncommon: 0.9,
      rare: 0.8,
      epic: 0.7,
      legendary: 0.6,
    }[String(tier || "common").toLowerCase()] ?? 1.0;

  chance *= tierMult;

  // Level penalty (soft curve)
  const levelPenalty = Math.min(0.25, (lvl - 1) / 370);
  chance *= 1 - levelPenalty;

  return Math.max(0.02, Math.min(0.9, chance));
}

module.exports = {
  loadDex,
  rollLevel,
  computeStats,
  getMovesForLevel,
  catchChance,
};
