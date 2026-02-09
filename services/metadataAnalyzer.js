async function analyzeMetadata(pkgData) {
  let reasons = [];
  let riskMultiplier = 1.0;

  let scriptFactor = 1.0;
  if (pkgData.scripts?.postinstall) {
    scriptFactor *= 2.2;
    reasons.push("Suspicious postinstall script detected");
  }
  if (pkgData.scripts?.preinstall) {
    scriptFactor *= 1.6;
    reasons.push("Preinstall script detected");
  }
  if (pkgData.scripts?.install) {
    scriptFactor *= 1.3;
    reasons.push("Install script detected");
  }
  riskMultiplier *= scriptFactor;

  const maintainers = Array.isArray(pkgData.maintainers)
    ? pkgData.maintainers.length
    : 0;

  if (maintainers === 0) {
    riskMultiplier *= 2.8;
    reasons.push("No active maintainers");
  } else if (maintainers === 1) {
    riskMultiplier *= 1.9;
    reasons.push("Single maintainer (single point of failure)");
  } else if (maintainers === 2) {
    riskMultiplier *= 1.35;
    reasons.push("Limited maintainer team");
  } else if (maintainers >= 5) {
    riskMultiplier *= 0.65;
    reasons.push("Well-maintained package (multiple maintainers)");
  } else if (maintainers >= 3) {
    riskMultiplier *= 0.82;
    reasons.push("Moderate maintainer team");
  }

  const latestVersion = pkgData.time?.[pkgData.version];
  if (latestVersion) {
    const daysOld =
      (Date.now() - new Date(latestVersion)) / (1000 * 60 * 60 * 24);
    if (daysOld < 7) {
      riskMultiplier *= 1.45;
      reasons.push("Published <7 days ago (supply chain risk)");
    } else if (daysOld > 730) {
      riskMultiplier *= 1.7;
      reasons.push("Not updated for 2+ years (stale)");
    } else if (daysOld > 365) {
      riskMultiplier *= 1.35;
      reasons.push("Not updated for 1+ years");
    }
  }

  const downloads = pkgData.downloads || 0;
  let downloadFactor = 1.0;

  if (downloads < 50) {
    downloadFactor = 2.1;
    reasons.push("Extremely low download count (<50)");
  } else if (downloads < 500) {
    downloadFactor = 1.7;
    reasons.push("Very low download count");
  } else if (downloads < 10_000) {
    downloadFactor = 1.25;
    reasons.push("Low download count");
  } else if (downloads > 100_000_000) {
    downloadFactor = 0.45;
    reasons.push("Massive adoption (100M+ downloads)");
  } else if (downloads > 10_000_000) {
    downloadFactor = 0.55;
    reasons.push("Very high adoption (10M+ downloads)");
  } else if (downloads > 1_000_000) {
    downloadFactor = 0.72;
    reasons.push("High adoption (1M+ downloads)");
  } else if (downloads > 100_000) {
    downloadFactor = 0.88;
    reasons.push("Moderate adoption (100K+ downloads)");
  }
  riskMultiplier *= downloadFactor;

  if (!pkgData.publisher) {
    riskMultiplier *= 1.18;
    reasons.push("No publisher information");
  }

  if (!pkgData.repository) {
    riskMultiplier *= 1.25;
    reasons.push("No repository link");
  }

  if (!pkgData.description) {
    riskMultiplier *= 1.12;
    reasons.push("No package description");
  }

  const riskScore = Math.round(
    Math.min(
      100,
      Math.max(0, Math.log2(Math.max(1, riskMultiplier)) * 20 + 10),
    ),
  );

  const getRiskLabel = (score) => {
    if (score >= 80) return "CRITICAL RISK";
    if (score >= 50) return "HIGH RISK";
    if (score >= 20) return "MEDIUM RISK";
    return "LOW RISK";
  };

  const getRiskEmoji = (score) => {
    if (score >= 80) return "🔴";
    if (score >= 50) return "🟠";
    if (score >= 20) return "🟡";
    return "🟢";
  };

  const riskLabel = getRiskLabel(riskScore);
  const emoji = getRiskEmoji(riskScore);
  const status = `${emoji} ${riskLabel}`;

  const meterLength = 20;
  const filledLength = Math.round((riskScore / 100) * meterLength);
  const riskMeter =
    "█".repeat(filledLength) + "░".repeat(meterLength - filledLength);

  return {
    riskScore,
    riskLabel,
    status,
    riskMeter,
    reasons,
    trustScore: Math.max(0, 100 - riskScore),
    analysis: `${pkgData.name}: ${status} (${riskScore}/100)`,
  };
}

module.exports = { analyzeMetadata };
