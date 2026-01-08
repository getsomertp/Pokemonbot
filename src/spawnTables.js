// You can tune these later, or map specific Pokémon to tiers.
const TIERS = [
  { tier: "common", weight: 700, basePoints: 10 },
  { tier: "uncommon", weight: 200, basePoints: 25 },
  { tier: "rare", weight: 80, basePoints: 60 },
  { tier: "epic", weight: 18, basePoints: 150 },
  { tier: "legendary", weight: 2, basePoints: 400 }
];

function pickTier(rng = Math.random) {
  const total = TIERS.reduce((s, t) => s + t.weight, 0);
  let roll = Math.floor(rng() * total);
  for (const t of TIERS) {
    roll -= t.weight;
    if (roll < 0) return t;
  }
  return TIERS[0];
}

function basePointsForTier(tier) {
  return TIERS.find(t => t.tier === tier)?.basePoints ?? 10;
}

module.exports = { TIERS, pickTier, basePointsForTier };
