const { clamp } = require("./util");
const { basePointsForTier } = require("./spawnTables");

/**
 * Points design:
 * - Tier base points
 * - Shiny multiplier x10 (big swing)
 * - Speed bonus up to +50%
 * - Streak bonus +2% per streak, capped +20%
 */
function computePoints({ tier, isShiny, speedMs, streak }) {
  const base = basePointsForTier(tier);

  // Speed bonus: 0% to 50%
  const speedSec = speedMs / 1000;
  let speedBonusPct = 0;
  if (speedSec <= 5) speedBonusPct = 0.5;
  else if (speedSec <= 15) speedBonusPct = 0.25;
  else if (speedSec <= 30) speedBonusPct = 0.10;
  else speedBonusPct = 0;

  // Streak bonus: +2% per streak, capped 20%
  const streakBonusPct = clamp((streak || 0) * 0.02, 0, 0.20);

  let points = base * (1 + speedBonusPct + streakBonusPct);

  // Shiny multiplier
  if (isShiny) points *= 10;

  return Math.max(1, Math.round(points));
}

module.exports = { computePoints };
