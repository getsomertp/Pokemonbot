const { prisma } = require("./prisma");
const { envInt } = require("./util");
const { pickTier } = require("./spawnTables");
const { computePoints } = require("./points");

const { simulateBattle, buildBattleMonFromDex } = require("./battle");

// Gen 1 dex helpers (reads data/gen1.dex.json)
const dex = require("./dex");

function randInt(max) {
  return Math.floor(Math.random() * max);
}

function leaderAdjKey(userId) {
  return `lp_adj:${userId}`;
}

function activeMonKey(userId) {
  return `active_mon:${userId}`;
}

async function getLeaderAdj(userId) {
  const row = await prisma.setting.findUnique({ where: { key: leaderAdjKey(userId) } });
  if (!row?.value) return 0;
  const n = Number(row.value);
  return Number.isFinite(n) ? Math.trunc(n) : 0;
}


class Game {
  constructor() {
    // Randomized spawn pacing is controlled by the server scheduler.
    // These defaults are also exposed for convenience.
    this.spawnDelayMinSeconds = envInt("SPAWN_DELAY_MIN_SECONDS", 60); // 1 minute
    this.spawnDelayMaxSeconds = envInt("SPAWN_DELAY_MAX_SECONDS", 900); // 15 minutes
    this.despawnSeconds = envInt("DESPAWN_SECONDS", 45);
    this.shinyOdds = envInt("SHINY_ODDS", 512);

    // optional tuning
    this.levelMin = envInt("LEVEL_MIN", 3);
    this.levelMax = envInt("LEVEL_MAX", 75);
  }

  nextSpawnDelayMs() {
    const min = Math.max(5, this.spawnDelayMinSeconds);
    const max = Math.max(min, this.spawnDelayMaxSeconds);
    const secs = min + Math.floor(Math.random() * (max - min + 1));
    return secs * 1000;
  }

  async getOrCreateKickUser(username, platformUserId = null) {
    const handle = String(username || "").toLowerCase();
    const existing = await prisma.userIdentity.findUnique({
      where: { platform_handle: { platform: "kick", handle } },
      include: { user: true }
    });

    if (existing?.user) return existing.user;

    const created = await prisma.user.create({
      data: {
        displayName: username,
        identities: {
          create: {
            platform: "kick",
            handle,
            platformUserId: platformUserId ? String(platformUserId) : null
          }
        }
      }
    });

    return created;
  }

  async getActiveSpawn() {
    const now = new Date();
    return prisma.spawn.findFirst({
      where: {
        caughtAt: null,
        expiresAt: { gt: now }
      },
      orderBy: { spawnedAt: "desc" }
    });
  }

  /**
   * Spawn:
   * - picks a Gen 1 mon from data/gen1.dex.json
   * - rolls a level
   * - computes stats + moves
   * - stores them on Spawn so battles can use them later
   */
  async spawn() {
    const d = dex.loadDex();
    const p = d.pokemon[randInt(d.pokemon.length)];

    const tier = pickTier().tier;
    const isShiny = randInt(this.shinyOdds) === 0;

    // roll level (weighted), then clamp via env
    let level = dex.rollLevel();
    level = Math.max(this.levelMin, Math.min(this.levelMax, level));

    const stats = dex.computeStats(p.baseStats, level);
    // dex.getMovesForLevel() already returns fully-populated move objects.
    // (Previous builds treated these as IDs, which resulted in empty wild movesets.
    //  That made wild Pokémon never take a turn.)
    const moves = (dex.getMovesForLevel(p, level) || []).map((m) => ({
      id: m.id,
      name: m.name,
      power: m.power,
      accuracy: m.accuracy,
      pp: m.pp,
      type: m.type,
      damageClass: m.damageClass,
      priority: m.priority
    }));

    const spawnedAt = new Date();
    const expiresAt = new Date(spawnedAt.getTime() + this.despawnSeconds * 1000);

    const spawn = await prisma.spawn.create({
      data: {
        pokemon: p.name, // chat guesses this
        pokemonId: p.id, // stable dex id for future PvP/trainer battles
        tier,
        isShiny,
        level,
        catchRate: p.catchRate || 45,
        statsJson: stats,
        movesJson: moves,
        spawnedAt,
        expiresAt
      }
    });

    return spawn;
  }

  async ensureSpawnExists() {
    const active = await this.getActiveSpawn();
    return active || this.spawn();
  }

  /**
   * Catching:
   * - requires correct name
   * - then rolls catch chance based on (catchRate + level + tier [+ shiny])
   * - higher level = harder to catch
   * - higher level = more points
   */
  async tryCatch({ username, platformUserId, guessName }) {
    const spawn = await this.getActiveSpawn();
    if (!spawn) return { ok: false, reason: "no_spawn" };

    const guess = String(guessName || "").trim().toLowerCase();

    // If a name was provided, enforce it. If not, allow plain !catch (only one spawn exists at a time).
    if (guess) {
      if (guess !== String(spawn.pokemon || "").toLowerCase()) {
        return { ok: false, reason: "wrong_name" };
      }
    }

    // Level-based catch difficulty
    const chance = dex.catchChance({
      catchRate: spawn.catchRate || 45,
      level: spawn.level || 5,
      tier: spawn.tier || "common"
    });

    // Optional: shiny slightly harder
    const finalChance = spawn.isShiny ? Math.max(0.01, chance * 0.85) : chance;

    // Roll catch
    if (Math.random() > finalChance) {
      return { ok: false, reason: "catch_failed", chance: finalChance };
    }

    const user = await this.getOrCreateKickUser(username, platformUserId);

    const now = new Date();
    const speedMs = now.getTime() - new Date(spawn.spawnedAt).getTime();

    // streak: count catches within last 30 minutes (tune later)
    const thirtyMinAgo = new Date(Date.now() - 30 * 60 * 1000);
    const recentCatches = await prisma.catch.count({
      where: { userId: user.id, caughtAt: { gt: thirtyMinAgo } }
    });
    const streak = Math.min(recentCatches, 10);

    // Base points (your existing logic)
    let pointsEarned = computePoints({
      tier: spawn.tier,
      isShiny: spawn.isShiny,
      speedMs,
      streak
    });

    // Level bonus (tune however you want)
    pointsEarned += Math.floor((spawn.level || 5) / 5);

    // Transaction so only one person catches it
    const result = await prisma.$transaction(async (tx) => {
      const fresh = await tx.spawn.findUnique({ where: { id: spawn.id } });
      if (!fresh || fresh.caughtAt) return { ok: false, reason: "already_caught" };

      await tx.spawn.update({
        where: { id: spawn.id },
        data: { caughtAt: now, caughtBy: user.id }
      });

      // Initialize persistent HP on catch using stored spawn stats when possible.
      let hpMax = 0;
      try {
        hpMax = Math.floor(Number(spawn.statsJson?.hp || 0));
      } catch {}
      if (!hpMax) {
        const rebuilt = buildBattleMonFromDex({ nameOrId: spawn.pokemonId || spawn.pokemon, level: spawn.level || 5 });
        hpMax = Math.floor(Number(rebuilt?.stats?.hp || 0));
      }

      const c = await tx.catch.create({
        data: {
          userId: user.id,
          spawnId: spawn.id,
          pokemon: spawn.pokemon,
          tier: spawn.tier,
          isShiny: spawn.isShiny,
          level: spawn.level, // ✅ saved for history/PvP selection later
          hpMax: hpMax || null,
          hpCurrent: hpMax || null,
          pointsEarned,
          speedMs
        }
      });

      return { ok: true, catch: c, user, spawn };
    });

    return result;
  }

  async leaderboard(limit = 10) {
    const rows = await prisma.catch.groupBy({
      by: ["userId"],
      _sum: { pointsEarned: true },
      orderBy: { _sum: { pointsEarned: "desc" } },
      take: limit
    });

    const users = await prisma.user.findMany({
      where: { id: { in: rows.map((r) => r.userId) } }
    });

    const userMap = new Map(users.map((u) => [u.id, u]));

    const keys = rows.map((r) => leaderAdjKey(r.userId));

    const adjRows = await prisma.setting.findMany({ where: { key: { in: keys } } });
    const adjMap = new Map(adjRows.map((x) => [x.key, Math.trunc(Number(x.value) || 0)]));

    return rows.map((r, i) => ({
      rank: i + 1,
      userId: r.userId,
      name: userMap.get(r.userId)?.displayName || "unknown",
      points: (r._sum.pointsEarned || 0) + (adjMap.get(leaderAdjKey(r.userId)) || 0)
    }));
  }

  async userStats(username) {
    const handle = String(username || "").toLowerCase();
    const ident = await prisma.userIdentity.findUnique({
      where: { platform_handle: { platform: "kick", handle } },
      include: { user: true }
    });
    if (!ident?.user) return null;

    const [totalPoints, totalCatches, totalShinies] = await Promise.all([
      prisma.catch.aggregate({ where: { userId: ident.user.id }, _sum: { pointsEarned: true } }),
      prisma.catch.count({ where: { userId: ident.user.id } }),
      prisma.catch.count({ where: { userId: ident.user.id, isShiny: true } })
    ]);

    return {
      name: ident.user.displayName || username,
      points: (totalPoints._sum.pointsEarned || 0) + (await getLeaderAdj(ident.user.id)),
      catches: totalCatches,
      shinies: totalShinies
    };
  }

  // ---- Team selection (1 mon for now) ----
  async setActivePokemon(userId, pokemonNameOrId) {
    const key = activeMonKey(userId);
    const val = String(pokemonNameOrId || "").trim();
    if (!val) {
      await prisma.setting.delete({ where: { key } }).catch(() => {});
      return null;
    }
    await prisma.setting.upsert({
      where: { key },
      update: { value: val },
      create: { key, value: val }
    });
    return val;
  }

  async getActivePokemonChoice(userId) {
    const row = await prisma.setting.findUnique({ where: { key: activeMonKey(userId) } });
    return row?.value ? String(row.value) : null;
  }

  /**
   * Pick the user's battle mon from their catches.
   * - If they chose a species via !use, pick the highest level of that species.
   * - Otherwise, pick their highest level catch.
   */
  async getUserBattleMon(userId) {
    const choice = await this.getActivePokemonChoice(userId);
    const where = { userId };
    const rows = await prisma.catch.findMany({
      where,
      orderBy: [{ level: "desc" }, { caughtAt: "desc" }],
      take: 200
    });
    if (!rows.length) return null;

    let pick = null;
    if (choice) {
      const c = String(choice).toLowerCase();
      pick = rows.find((r) => String(r.pokemon || "").toLowerCase() === c);
    }
    if (!pick) pick = rows[0];

    const lvl = pick.level || 5;
    const mon = buildBattleMonFromDex({ nameOrId: pick.pokemon, level: lvl });
    if (!mon) return null;

    // Persistent HP: if missing (legacy rows), treat as full health.
    const maxHP = Number(mon.stats?.hp || 1);
    const curHP = Number(pick.hpCurrent);
    mon.hp = Number.isFinite(curHP) && curHP > 0 ? Math.min(Math.max(1, Math.floor(curHP)), maxHP) : maxHP;
    mon.maxHP = maxHP;

    return { mon, catchRow: pick };
  }

  /**
   * Battle the active spawn with the user's selected Pokémon.
   * If the user wins, we award a guaranteed catch (like a "battle-catch").
   */
  async battleActiveSpawn({ username, platformUserId }) {
    const spawn = await this.getActiveSpawn();
    if (!spawn) return { ok: false, reason: "no_spawn" };

    const user = await this.getOrCreateKickUser(username, platformUserId);
    const picked = await this.getUserBattleMon(user.id);
    if (!picked?.mon || !picked?.catchRow) return { ok: false, reason: "no_team" };
    const userMon = picked.mon;
    const userCatch = picked.catchRow;

    // Build wild mon from stored spawn stats/moves if available, else from dex.
    // NOTE: Prisma JSON fields can contain empty arrays/objects; treat those as "missing".
    const wild = {
      name: spawn.pokemon,
      level: spawn.level || 5,
      types: [],
      stats: spawn.statsJson || null,
      moves: spawn.movesJson || null
    };
    const hasStats = !!wild.stats && typeof wild.stats === "object" && Number(wild.stats.hp || 0) > 0;
    const hasMoves = Array.isArray(wild.moves) && wild.moves.length > 0;
    if (!hasStats || !hasMoves) {
      const rebuilt = buildBattleMonFromDex({ nameOrId: spawn.pokemonId || spawn.pokemon, level: spawn.level || 5 });
      if (rebuilt) {
        wild.types = rebuilt.types;
        wild.stats = rebuilt.stats;
        wild.moves = rebuilt.moves;
      }
    } else {
      // types aren't stored on spawn, so rebuild just for types
      const rebuilt = buildBattleMonFromDex({ nameOrId: spawn.pokemonId || spawn.pokemon, level: spawn.level || 5 });
      if (rebuilt) wild.types = rebuilt.types;
    }

    const sim = simulateBattle(userMon, wild, undefined, { mode: "wild", leftTrainerName: username, rightTrainerName: "Wild" });
    const userWon = sim.winner === "left";

    // Persist HP for the user's active Pokémon (and delete if it fainted).
    try {
      const newHp = Math.max(0, Math.floor(Number(sim.left?.hp ?? 0)));
      const newMax = Math.floor(Number(sim.left?.maxHP ?? 0)) || null;
      if (newHp <= 0) {
        await prisma.catch.delete({ where: { id: userCatch.id } }).catch(() => {});
      } else {
        await prisma.catch.update({ where: { id: userCatch.id }, data: { hpCurrent: newHp, hpMax: newMax } }).catch(() => {});
      }
    } catch {}

    if (!userWon) {
      return {
        ok: true,
        result: "lost",
        userMon: sim.left,
        wildMon: sim.right,
        log: sim.log,
        events: sim.events,
        spawn
      };
    }

    // User won: do a guaranteed catch transaction (only one person can win/catch)
    const now = new Date();
    const speedMs = now.getTime() - new Date(spawn.spawnedAt).getTime();

    // modest points for battling; catching points still apply
    const battleBonus = 3;

    const result = await prisma.$transaction(async (tx) => {
      const fresh = await tx.spawn.findUnique({ where: { id: spawn.id } });
      if (!fresh || fresh.caughtAt) return { ok: false, reason: "already_caught" };

      await tx.spawn.update({
        where: { id: spawn.id },
        data: { caughtAt: now, caughtBy: user.id }
      });

      // Use your existing points logic but add a small bonus for winning a battle
      let pointsEarned = computePoints({
        tier: spawn.tier,
        isShiny: spawn.isShiny,
        speedMs,
        streak: 0
      });
      pointsEarned += Math.floor((spawn.level || 5) / 5);
      pointsEarned += battleBonus;

      let hpMax = 0;
      try {
        hpMax = Math.floor(Number(spawn.statsJson?.hp || 0));
      } catch {}
      if (!hpMax) {
        const rebuilt = buildBattleMonFromDex({ nameOrId: spawn.pokemonId || spawn.pokemon, level: spawn.level || 5 });
        hpMax = Math.floor(Number(rebuilt?.stats?.hp || 0));
      }

      const c = await tx.catch.create({
        data: {
          userId: user.id,
          spawnId: spawn.id,
          pokemon: spawn.pokemon,
          tier: spawn.tier,
          isShiny: spawn.isShiny,
          level: spawn.level,
          hpMax: hpMax || null,
          hpCurrent: hpMax || null,
          pointsEarned,
          speedMs
        }
      });

      return { ok: true, catch: c };
    });

    if (!result.ok) return result;

    return {
      ok: true,
      result: "won",
      userMon: sim.left,
      wildMon: sim.right,
      log: sim.log,
        events: sim.events,
      spawn,
      catch: result.catch
    };
  }

  /**
   * Trainer vs Trainer battle (1 Pokémon each, for now).
   * No catching occurs. Returns simulation events for the overlay.
   */
  async battleTrainers({ challengerUserId, challengerName, opponentUserId, opponentName }) {
    const aPick = await this.getUserBattleMon(challengerUserId);
    const bPick = await this.getUserBattleMon(opponentUserId);
    const aMon = aPick?.mon;
    const bMon = bPick?.mon;
    if (!aMon || !bMon || !aPick?.catchRow || !bPick?.catchRow) {
      return { ok: false, reason: "no_team" };
    }

    const sim = simulateBattle(aMon, bMon, undefined, { mode: "trainer", leftTrainerName: challengerName, rightTrainerName: opponentName });
    const aWon = sim.winner === "left";

    // Persist HP for both trainers' active Pokémon (delete if fainted).
    try {
      const aHp = Math.max(0, Math.floor(Number(sim.left?.hp ?? 0)));
      const aMax = Math.floor(Number(sim.left?.maxHP ?? 0)) || null;
      if (aHp <= 0) await prisma.catch.delete({ where: { id: aPick.catchRow.id } }).catch(() => {});
      else await prisma.catch.update({ where: { id: aPick.catchRow.id }, data: { hpCurrent: aHp, hpMax: aMax } }).catch(() => {});
    } catch {}
    try {
      const bHp = Math.max(0, Math.floor(Number(sim.right?.hp ?? 0)));
      const bMax = Math.floor(Number(sim.right?.maxHP ?? 0)) || null;
      if (bHp <= 0) await prisma.catch.delete({ where: { id: bPick.catchRow.id } }).catch(() => {});
      else await prisma.catch.update({ where: { id: bPick.catchRow.id }, data: { hpCurrent: bHp, hpMax: bMax } }).catch(() => {});
    } catch {}
    return {
      ok: true,
      result: aWon ? "challenger" : "opponent",
      winnerName: aWon ? (challengerName || aMon.name) : (opponentName || bMon.name),
      loserName: aWon ? (opponentName || bMon.name) : (challengerName || aMon.name),
      challengerMon: sim.left,
      opponentMon: sim.right,
      events: sim.events,
      log: sim.log
    };
  }
}

module.exports = { Game };
