async function analyzeMetadata(pkgData) {
  let riskScore = 0;
  let reasons = [];

  // 1. DOWNLOADS (Popularity = Trust)
  const downloads = pkgData.downloads || 0;
  if (downloads > 1_000_000) {
    riskScore -= 3; // Very popular
  } else if (downloads < 100) {
    riskScore += 4; //Brand new/risky
    reasons.push("Very low downloads");
  }

  //2. MALICIOUS SCRIPTS
  if (pkgData.scripts?.postinstall) {
    riskScore += 5; // Postinstall = common malware vector
    reasons.push("Suspicious postinstall script");
  }

  // 3. GHOST PUBLISHER
  if (!pkgData.publisher) {
    riskScore += 2;
    reasons.push("No publisher info");
  }

  // 4. SINGLE MAINTAINER
  if (pkgData.maintainers?.length === 1) {
    riskScore += 2;
    reasons.push("Single maintainer");
  } else if (pkgData.maintainers?.length === 0) {
    riskScore += 3;
    reasons.push("No maintainers");
  }

  // 5. RECENT PUBLISH (Supply chain risk)
  const latestVersion = pkgData.time?.[pkgData.version];
  if (latestVersion) {
    const daysOld =
      (Date.now() - new Date(latestVersion)) / (1000 * 60 * 60 * 24);
    if (daysOld < 7) {
      riskScore += 3;
      reasons.push("Published <7 days ago");
    }
  }

  // 5. FINAL STATUS
  const status =
    riskScore <= -2
      ? "🟢 LOW RISK"
      : riskScore <= 2
        ? "🟡 MEDIUM RISK"
        : "🔴 HIGH RISK";

  return {
    riskScore: Math.max(-5, Math.min(10, riskScore)), // -5 to +10
    status,
    reasons,
    trustScore: Math.max(0, 100 - riskScore * 8), // 0-100%
    analysis: `${pkgData.name}: ${status} (${riskScore})`,
  };
}

module.exports = { analyzeMetadata };
