const { prisma } = require("./prisma");
const pokedex = require("./pokedex");
const { envInt } = require("./util");
const { pickTier } = require("./spawnTables");
const { computePoints } = require("./points");

function randInt(max) {
  return Math.floor(Math.random() * max);
}

class Game {
  constructor() {
    this.spawnIntervalSeconds = envInt("SPAWN_INTERVAL_SECONDS", 90);
    this.despawnSeconds = envInt("DESPAWN_SECONDS", 45);
    this.shinyOdds = envInt("SHINY_ODDS", 512);
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

  async spawn() {
    const pokemon = pokedex[randInt(pokedex.length)];
    const tier = pickTier().tier;
    const isShiny = randInt(this.shinyOdds) === 0;

    const spawnedAt = new Date();
    const expiresAt = new Date(spawnedAt.getTime() + this.despawnSeconds * 1000);

    const spawn = await prisma.spawn.create({
      data: { pokemon, tier, isShiny, spawnedAt, expiresAt }
    });

    return spawn;
  }

  async ensureSpawnExists() {
    const active = await this.getActiveSpawn();
    return active || this.spawn();
  }

  async tryCatch({ username, platformUserId, guessName }) {
    const spawn = await this.getActiveSpawn();
    if (!spawn) return { ok: false, reason: "no_spawn" };

    const guess = String(guessName || "").trim().toLowerCase();
    if (!guess) return { ok: false, reason: "no_guess" };

    if (guess !== spawn.pokemon.toLowerCase()) {
      return { ok: false, reason: "wrong_name" };
    }

    const user = await this.getOrCreateKickUser(username, platformUserId);

    const now = new Date();
    const speedMs = now.getTime() - new Date(spawn.spawnedAt).getTime();

    // streak = consecutive catches without missing a spawn (simple version):
    // count catches within last 30 minutes (tune later)
    const thirtyMinAgo = new Date(Date.now() - 30 * 60 * 1000);
    const recentCatches = await prisma.catch.count({
      where: { userId: user.id, caughtAt: { gt: thirtyMinAgo } }
    });
    const streak = Math.min(recentCatches, 10); // cap for bonus calc

    const pointsEarned = computePoints({
      tier: spawn.tier,
      isShiny: spawn.isShiny,
      speedMs,
      streak
    });

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
          speedMs
        }
      });

      return { ok: true, catch: c, user, spawn };
    });

    return result;
  }

  async leaderboard(limit = 10) {
    // Sum points per user
    const rows = await prisma.catch.groupBy({
      by: ["userId"],
      _sum: { pointsEarned: true },
      orderBy: { _sum: { pointsEarned: "desc" } },
      take: limit
    });

    const users = await prisma.user.findMany({
      where: { id: { in: rows.map(r => r.userId) } }
    });

    const userMap = new Map(users.map(u => [u.id, u]));

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
