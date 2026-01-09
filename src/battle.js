// src/battle.js
// Minimal, Gen-1-inspired battle simulator (data-driven, bot-friendly).
// One Pokémon per side. Deterministic if you provide a seeded rng.

const dex = require("./dex");

// --- Gen 1 type chart multipliers (attack -> defense) ---
// Missing entries are treated as 1x.
const TYPE_CHART = {
  NORMAL: { ROCK: 0.5, GHOST: 0 },
  FIRE: { FIRE: 0.5, WATER: 0.5, GRASS: 2, ICE: 2, BUG: 2, ROCK: 0.5, DRAGON: 0.5 },
  WATER: { FIRE: 2, WATER: 0.5, GRASS: 0.5, GROUND: 2, ROCK: 2, DRAGON: 0.5 },
  ELECTRIC: { WATER: 2, ELECTRIC: 0.5, GRASS: 0.5, GROUND: 0, FLYING: 2, DRAGON: 0.5 },
  GRASS: { FIRE: 0.5, WATER: 2, GRASS: 0.5, POISON: 0.5, GROUND: 2, FLYING: 0.5, BUG: 0.5, ROCK: 2, DRAGON: 0.5 },
  ICE: { FIRE: 0.5, WATER: 0.5, GRASS: 2, GROUND: 2, FLYING: 2, DRAGON: 2 },
  FIGHTING: { NORMAL: 2, ICE: 2, ROCK: 2, POISON: 0.5, FLYING: 0.5, PSYCHIC: 0.5, GHOST: 0 },
  POISON: { GRASS: 2, POISON: 0.5, GROUND: 0.5, ROCK: 0.5, GHOST: 0.5 },
  GROUND: { FIRE: 2, ELECTRIC: 2, GRASS: 0.5, POISON: 2, FLYING: 0, BUG: 0.5, ROCK: 2 },
  FLYING: { ELECTRIC: 0.5, GRASS: 2, FIGHTING: 2, BUG: 2, ROCK: 0.5 },
  PSYCHIC: { FIGHTING: 2, POISON: 2, PSYCHIC: 0.5 },
  BUG: { FIRE: 0.5, GRASS: 2, FIGHTING: 0.5, POISON: 2, FLYING: 0.5, PSYCHIC: 2 },
  ROCK: { FIRE: 2, ICE: 2, FLYING: 2, BUG: 2, FIGHTING: 0.5, GROUND: 0.5 },
  GHOST: { NORMAL: 0, PSYCHIC: 0, GHOST: 2 },
  DRAGON: { DRAGON: 2 }
};

function multOne(moveType, defType) {
  const row = TYPE_CHART[String(moveType || "").toUpperCase()];
  const key = String(defType || "").toUpperCase();
  if (!row) return 1;
  if (row[key] === undefined) return 1;
  return row[key];
}

function typeMultiplier(moveType, defenderTypes) {
  let m = 1;
  for (const t of defenderTypes || []) m *= multOne(moveType, t);
  return m;
}

function hasSTAB(moveType, attackerTypes) {
  const mt = String(moveType || "").toUpperCase();
  return (attackerTypes || []).some((t) => String(t).toUpperCase() === mt);
}

function pickRandom(arr, rng) {
  if (!arr || !arr.length) return null;
  const i = Math.floor(rng() * arr.length);
  return arr[i];
}

function clamp(n, lo, hi) {
  return Math.max(lo, Math.min(hi, n));
}

// Simple battle RNG wrapper; pass a seeded rng for determinism.
function defaultRng() {
  return Math.random();
}

function calcDamage({
  attacker,
  defender,
  move,
  rng
}) {
  const r = rng || defaultRng;
  const power = Number(move?.power || 0);
  if (!power || power <= 0) return { damage: 0, hit: true, crit: false, mult: 1 };

  const acc = move?.accuracy == null ? 100 : Number(move.accuracy);
  if (acc > 0) {
    const roll = Math.floor(r() * 100) + 1;
    if (roll > acc) return { damage: 0, hit: false, crit: false, mult: 1 };
  }

  const lvl = clamp(Number(attacker.level || 5), 1, 100);
  const cls = String(move?.damageClass || move?.damageClassName || move?.damage_class || "physical").toLowerCase();
  const A = cls === "special" ? Number(attacker.stats?.spAtk || attacker.stats?.spA || 1) : Number(attacker.stats?.atk || 1);
  const D = cls === "special" ? Number(defender.stats?.spDef || defender.stats?.spD || 1) : Number(defender.stats?.def || 1);

  const levelFactor = Math.floor((2 * lvl) / 5) + 2;
  const base = Math.floor(Math.floor((levelFactor * power * Math.max(1, A)) / Math.max(1, D)) / 50) + 2;

  const stab = hasSTAB(move.type, attacker.types) ? 1.5 : 1;
  const mult = typeMultiplier(move.type, defender.types);
  const crit = r() < 1 / 16; // ~6.25%
  const critMult = crit ? 1.5 : 1;
  const rand = 0.85 + r() * 0.15;

  const dmg = Math.max(1, Math.floor(base * stab * mult * critMult * rand));
  return { damage: mult === 0 ? 0 : dmg, hit: true, crit, mult };
}

function chooseMove(poke, rng) {
  const moves = (poke.moves || []).filter((m) => Number(m?.power || 0) > 0);
  // If no damaging moves exist (shouldn't happen with our dex), fall back to any move.
  return pickRandom(moves.length ? moves : poke.moves, rng) || null;
}

/**
 * simulateBattle
 * @param {object} a - { name, level, types:[], stats:{hp,atk,def,spAtk,spDef,spe}, moves:[] }
 * @param {object} b - same shape
 * @param {function} rng - () => number in [0,1)
 */
function simulateBattle(a, b, rng = defaultRng) {
  const left = JSON.parse(JSON.stringify(a));
  const right = JSON.parse(JSON.stringify(b));
  left.maxHP = Number(left.stats?.hp || 1);
  right.maxHP = Number(right.stats?.hp || 1);
  left.hp = left.maxHP;
  right.hp = right.maxHP;

  const log = [];
  const events = [];
  const maxTurns = 50;

  /**
   * Push an animation frame for the overlay.
   *
   * action: {
   *   kind: 'start'|'sendout'|'use'|'hit'|'miss'|'noeffect'|'pause'|'faint'|'end',
   *   attacker?: 'L'|'R',
   *   defender?: 'L'|'R',
   *   moveName?: string,
   *   damage?: number,
   *   crit?: boolean,
   *   mult?: number
   * }
   */
  function pushEvent(text, action, durationMs) {
    events.push({
      text: text == null ? "" : String(text),
      leftHp: left.hp,
      leftMax: left.maxHP,
      rightHp: right.hp,
      rightMax: right.maxHP,
      action: action || null,
      durationMs: durationMs == null ? 1000 : Number(durationMs)
    });
  }

  // Opening sequence (lets overlay do "send out" animations)
  // Slightly slower pacing so OBS viewers can read each line.
  // A bit slower so the viewer can register the scene.
  pushEvent(`A wild ${right.name} appeared!`, { kind: "start", defender: "R" }, 1600);
  pushEvent(`Go! ${left.name}!`, { kind: "sendout", attacker: "L" }, 1600);

  for (let turn = 1; turn <= maxTurns; turn++) {
    if (left.hp <= 0 || right.hp <= 0) break;

    const lMove = chooseMove(left, rng);
    const rMove = chooseMove(right, rng);

    // Determine order: priority then speed then coin flip
    const lPri = Number(lMove?.priority || 0);
    const rPri = Number(rMove?.priority || 0);
    const lSpe = Number(left.stats?.spe || left.stats?.spd || 1);
    const rSpe = Number(right.stats?.spe || right.stats?.spd || 1);

    const first =
      lPri !== rPri
        ? (lPri > rPri ? "L" : "R")
        : lSpe !== rSpe
          ? (lSpe > rSpe ? "L" : "R")
          : (rng() < 0.5 ? "L" : "R");

    const order = first === "L"
      ? [["L", left, "R", right, lMove], ["R", right, "L", left, rMove]]
      : [["R", right, "L", left, rMove], ["L", left, "R", right, lMove]];

    for (const [attSide, att, defSide, def, mv] of order) {
      if (att.hp <= 0 || def.hp <= 0) continue;
      if (!mv) continue;

      // 1) "X used MOVE!"
      // "X used MOVE!" gets its own beat, like the mainline games.
      // Give the "used" line enough time to read.
      pushEvent(`${att.name} used ${mv.name}!`, { kind: "use", attacker: attSide, defender: defSide, moveName: mv.name }, 1900);
      if (turn <= 6) log.push(`${att.name} used ${mv.name}!`);

      const res = calcDamage({ attacker: att, defender: def, move: mv, rng });

      // 2) Outcome frame (damage/effectiveness/etc)
      if (!res.hit) {
        pushEvent(`But it missed!`, { kind: "miss", attacker: attSide, defender: defSide, moveName: mv.name }, 1800);
        if (turn <= 6) log.push("But it missed!");
        continue;
      }

      if (res.mult === 0) {
        pushEvent(`It had no effect!`, { kind: "noeffect", attacker: attSide, defender: defSide, moveName: mv.name, mult: 0 }, 1800);
        if (turn <= 6) log.push("It had no effect!");
        continue;
      }

      def.hp = Math.max(0, def.hp - res.damage);

      const lines = [];
      lines.push(`-${res.damage} HP!`);
      if (res.crit) lines.push("A critical hit!");
      if (res.mult >= 2) lines.push("It's super effective!");
      else if (res.mult > 0 && res.mult <= 0.5) lines.push("It's not very effective…");

      // Separate outcome beat: damage + crit/effectiveness + HP bar ticks down.
      pushEvent(lines.join("\n"), { kind: "hit", attacker: attSide, defender: defSide, moveName: mv.name, damage: res.damage, crit: !!res.crit, mult: res.mult }, 1900);
      if (turn <= 6) log.push(lines.join(" "));

      // Tiny pause before KO/final texts (feels more like Pokémon)
      if (def.hp <= 0) {
        // A tiny breath before the KO text.
        pushEvent("", { kind: "pause" }, 900);
        pushEvent(`${def.name} fainted!`, { kind: "faint", attacker: attSide, defender: defSide }, 1800);
        break;
      }
    }
  }

  const winner =
    left.hp > 0 && right.hp <= 0 ? "left"
    : right.hp > 0 && left.hp <= 0 ? "right"
    : left.hp >= right.hp ? "left"
    : "right";

  // Small pause before the win text
  pushEvent("", { kind: "pause" }, 900);
  pushEvent(winner === "left" ? `${left.name} wins!` : `${right.name} wins!`, { kind: "end" }, 2000);

  return {
    winner,
    left: { name: left.name, level: left.level, hp: left.hp, maxHP: left.maxHP },
    right: { name: right.name, level: right.level, hp: right.hp, maxHP: right.maxHP },
    log,
    events
  };
}

function buildBattleMonFromDex({ nameOrId, level }) {
  const d = dex.loadDex();
  const key = String(nameOrId || "");
  const mon = d.pokemon.find((p) => p.id === key) || d.pokemon.find((p) => String(p.name).toLowerCase() === key.toLowerCase());
  if (!mon) return null;

  const lvl = clamp(Number(level || 5), 1, 100);
  const stats = dex.computeStats(mon.baseStats, lvl);
  const moveIds = dex.getMovesForLevel(mon, lvl);
  const moves = moveIds
    .map((id) => mon.moves?.[id])
    .filter(Boolean)
    .map((m) => ({
      id: m.id,
      name: m.name,
      power: m.power,
      accuracy: m.accuracy,
      pp: m.pp,
      type: m.type,
      damageClass: m.damageClass,
      priority: m.priority
    }))
    .slice(0, 4);

  return {
    id: mon.id,
    name: mon.name,
    level: lvl,
    types: (mon.types || []).map((t) => String(t).toUpperCase()),
    stats,
    moves
  };
}

module.exports = {
  simulateBattle,
  buildBattleMonFromDex,
  typeMultiplier
};
