const { prisma } = require("./prisma");
const { envInt } = require("./util");
const { pickTier } = require("./spawnTables");
const { computePoints } = require("./points");

// NEW: Gen 1 dex helpers (reads data/gen1.dex.json)
const dex = require("./dex");

function randInt(max) {
  return Math.floor(Math.random() * max);
}

class Game {
  constructor() {
    this.spawnIntervalSeconds = envInt("SPAWN_INTERVAL_SECONDS", 90);
    this.despawnSeconds = envInt("DESPAWN_SECONDS", 45);
    this.shinyOdds = envInt("SHINY_ODDS", 512);

    // optional tuning
    this.levelMin = envInt("LEVEL_MIN", 3);
    this.levelMax = envInt("LEVEL_MAX", 75);
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
   * NEW SPAWN:
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
    const moveIds = dex.getMovesForLevel(p, level);

    // store move objects (name/power/accuracy/type/etc) for quick use later
    const moves = moveIds
      .map((id) => p.moves?.[id])
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
      }));

    const spawnedAt = new Date();
    const expiresAt = new Date(spawnedAt.getTime() + this.despawnSeconds * 1000);

    const spawn = await prisma.spawn.create({
      data: {
        pokemon: p.name,       // keep string for chat guessing
        pokemonId: p.id,       // stable id for battles
        tier,
        isShiny,
        level,
        catchRate: p.catchRate || 45,
        statsJson: stats,      // Json
        movesJson: moves,      // Json
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
   * - still requires correct name
   * - NEW: correct name triggers a catch roll based on (catchRate + level + tier)
   * - higher level = lower catch chance
   * - higher level = more points
   */
  async tryCatch({ username, platformUserId, guessName }) {
    const spawn = await this.getActiveSpawn();
    if (!spawn) return { ok: false, reason: "no_spawn" };

    const guess = String(guessName || "").trim().toLowerCase();
    if (!guess) return { ok: false, reason: "no_guess" };

    if (guess !== String(spawn.pokemon || "").toLowerCase()) {
      return { ok: false, reason: "wrong_name" };
    }

    // NEW: catch difficulty
    const chance = dex.catchChance({
      catchRate: spawn.catchRate || 45,
      level: spawn.level || 5,
      tier: spawn.tier || "common"
    });

    // If shiny, make it slightly harder (optional)
    const finalChance = spawn.isShiny ? Math.max(0.01, chance * 0.85) : chance;

    // roll
    if (Math.random() > finalChance) {
      return { ok: false, reason: "catch_failed", chance: finalChance };
    }

    const user = await this.getOrCreateKickUser(username, platformUserId);

    const now = new Date();
    const speedMs = now.getTime() - new Date(spawn.spawnedAt).getTime();

    // streak = consecutive catches without missing a spawn (simple version):
    const thirtyMinAgo = new Date(Date.now() - 30 * 60 * 1000);
    const recentCatches = await prisma.catch.count({
      where: { userId: user.id, caughtAt: { gt: thirtyMinAgo } }
    });
    const streak = Math.min(recentCatches, 10);

    // base points (your existing logic)
    let pointsEarned = computePoints({
      tier: spawn.tier,
      isShiny: spawn.isShiny,
      speedMs,
      streak
    });

    // NEW: level bonus points (tune however you like)
    // Example: +0..+15ish depending on level
    pointsEarned += Math.floor((spawn.level || 5) / 5);

    // Make sure only one person can catch: transactional update
    const result = await prisma.$transaction(async (tx) => {
      const fresh = await tx.spawn.findUnique({ where: { id: spawn.id } });
      if (!fresh || fresh.caughtAt) return { ok: false, reason: "already_caught" };

      await tx.spawn.update({
        where: { id: spawn.id },
        data: { caughtAt: now, caughtBy: user.id }
      });

      const c = await tx.catch.create({
        data: {
          userId: user.id,
          spawnId: spawn.id,
          pokemon: spawn.pokemon,
          tier: spawn.tier,
          isShiny: spawn.isShiny,
          pointsEarned,
          speedMs,

          // OPTIONAL: store level for history (requires Catch model field)
          // level: spawn.level
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

    return rows.map((r, i) => ({
      rank: i + 1,
      userId: r.userId,
      name: userMap.get(r.userId)?.displayName || "unknown",
      points: r._sum.pointsEarned || 0
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
      points: totalPoints._sum.pointsEarned || 0,
      catches: totalCatches,
      shinies: totalShinies
    };
  }
}

module.exports = { Game };
