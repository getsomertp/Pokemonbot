/**
 * Builds a Gen 1 dex JSON (151 mons) with:
 * - base stats
 * - types
 * - base catch rate
 * - level-up learnset (move names)
 * - move data (power/accuracy/pp/type/damage_class)
 *
 * Run locally:
 *   node scripts/buildGen1Dex.js
 *
 * Output:
 *   data/gen1.dex.json
 */
const fs = require("fs");
const path = require("path");

const OUT_PATH = path.join(__dirname, "..", "data", "gen1.dex.json");
const API = "https://pokeapi.co/api/v2";

// Node 18+ has fetch globally
if (typeof fetch !== "function") {
  throw new Error("This script requires Node 18+ (global fetch).");
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function toId(name) {
  return String(name).toLowerCase().replace(/[^a-z0-9]+/g, "-");
}

async function fetchJson(url, tries = 5) {
  let lastErr;
  for (let i = 0; i < tries; i++) {
    try {
      const res = await fetch(url, { headers: { "User-Agent": "gen1-dex-builder" } });
      if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText} for ${url}`);
      return await res.json();
    } catch (e) {
      lastErr = e;
      await sleep(300 + i * 500);
    }
  }
  throw lastErr;
}

async function main() {
  console.log("Fetching Gen 1 species list...");
  const gen1 = await fetchJson(`${API}/generation/1/`);

  // species list includes names; we want the corresponding /pokemon/{name} for stats/types
  const speciesNames = gen1.pokemon_species
    .map((s) => s.name)
    // Gen 1 is already 151, but keep stable ordering by national dex id:
    .sort((a, b) => {
      const na = a.includes("-") ? a.split("-")[0] : a;
      const nb = b.includes("-") ? b.split("-")[0] : b;
      return na.localeCompare(nb);
    });

  // Move cache to avoid refetching move details
  const moveCache = new Map();

  async function getMove(moveName) {
    const key = toId(moveName);
    if (moveCache.has(key)) return moveCache.get(key);

    const data = await fetchJson(`${API}/move/${key}/`);
    const move = {
      name: data.name,
      id: toId(data.name),
      power: data.power ?? null,
      accuracy: data.accuracy ?? null,
      pp: data.pp ?? null,
      priority: data.priority ?? 0,
      type: data.type?.name ?? null,
      damageClass: data.damage_class?.name ?? null, // physical/special/status
      meta: {
        ailment: data.meta?.ailment?.name ?? null,
        critRate: data.meta?.crit_rate ?? 0,
        flinchChance: data.meta?.flinch_chance ?? 0
      }
    };

    moveCache.set(key, move);
    // polite rate limiting
    await sleep(80);
    return move;
  }

  async function buildPokemon(speciesName) {
    // 1) species endpoint gives catch_rate and dex numbers
    const species = await fetchJson(`${API}/pokemon-species/${toId(speciesName)}/`);
    const dexNum = species.pokedex_numbers?.find((p) => p.pokedex.name === "national")?.entry_number;

    // 2) pokemon endpoint gives base stats/types and moves with learn methods
    const pokemon = await fetchJson(`${API}/pokemon/${toId(speciesName)}/`);

    const baseStats = {};
    for (const s of pokemon.stats) {
      baseStats[s.stat.name] = s.base_stat; // hp, attack, defense, special-attack, special-defense, speed
    }

    const types = pokemon.types
      .sort((a, b) => a.slot - b.slot)
      .map((t) => t.type.name);

    // Build level-up learnset from version-group "red-blue" (Gen 1 games) if present,
    // else fallback to the first available version group.
    const vgPreferred = "red-blue";

    const learnset = [];
    for (const m of pokemon.moves) {
      const moveName = m.move.name;

      // pick level-up details
      const details = m.version_group_details
        .filter((d) => d.move_learn_method.name === "level-up")
        .map((d) => ({
          level: d.level_learned_at,
          versionGroup: d.version_group.name
        }));

      if (!details.length) continue;

      // choose best detail (prefer red-blue)
      let chosen = details.find((d) => d.versionGroup === vgPreferred);
      if (!chosen) chosen = details.sort((a, b) => a.level - b.level)[0];

      if (!chosen || chosen.level === 0) continue;

      learnset.push({ level: chosen.level, move: moveName });
    }

    // sort by level then name
    learnset.sort((a, b) => a.level - b.level || a.move.localeCompare(b.move));

    // Now fetch move details for all unique moves in learnset
    const uniqueMoves = [...new Set(learnset.map((x) => x.move))];

    const moves = {};
    for (const mv of uniqueMoves) {
      const mdata = await getMove(mv);
      moves[mdata.id] = mdata;
    }

    return {
      dex: dexNum ?? null,
      name: pokemon.name,
      id: toId(pokemon.name),
      types,
      catchRate: species.catch_rate ?? 45, // 3..255 typical
      baseStats: {
        hp: baseStats["hp"] ?? 50,
        atk: baseStats["attack"] ?? 50,
        def: baseStats["defense"] ?? 50,
        spa: baseStats["special-attack"] ?? 50,
        spd: baseStats["special-defense"] ?? 50,
        spe: baseStats["speed"] ?? 50
      },
      learnset: learnset.map((x) => ({ level: x.level, moveId: toId(x.move) })),
      // store moves referenced by learnset
      moves
    };
  }

  const dex = [];
  for (let i = 0; i < speciesNames.length; i++) {
    const name = speciesNames[i];
    console.log(`[${i + 1}/${speciesNames.length}] Building ${name}...`);
    try {
      const p = await buildPokemon(name);
      dex.push(p);
      await sleep(120);
    } catch (e) {
      console.error("Failed:", name, e.message || e);
      throw e;
    }
  }

  // sort by national dex number
  dex.sort((a, b) => (a.dex ?? 9999) - (b.dex ?? 9999));

  const out = {
    generatedAt: new Date().toISOString(),
    generation: 1,
    count: dex.length,
    pokemon: dex
  };

  fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
  fs.writeFileSync(OUT_PATH, JSON.stringify(out, null, 2), "utf8");
  console.log(`✅ Wrote ${OUT_PATH}`);
  console.log(`Moves cached: ${moveCache.size}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
