/**
 * Analyze package metadata and calculate industry-standard risk score
 * Risk Scale: 0-100 (Higher = More Dangerous)
 *   0-19:   LOW RISK (safe)
 *   20-49:  MEDIUM RISK (review before using)
 *   50-79:  HIGH RISK (careful consideration required)
 *   80-100: CRITICAL RISK (not recommended)
 */
async function analyzeMetadata(pkgData) {
  let riskScore = 0; // Start at 0 (safest)
  let reasons = [];

  // ================================================
  // RISK FACTORS (Increase Score)
  // ================================================

  // 1. CVE SEVERITY (Not present in metadata, handled separately)
  // Note: CVE count and severity are evaluated in auditPackage()

  // 2. MALICIOUS SCRIPTS - Postinstall scripts are common malware vectors
  if (pkgData.scripts?.postinstall) {
    riskScore += 20; // Major risk factor
    reasons.push("Suspicious postinstall script detected");
  }
  if (pkgData.scripts?.preinstall) {
    riskScore += 12;
    reasons.push("Preinstall script detected");
  }
  if (pkgData.scripts?.install) {
    riskScore += 8;
    reasons.push("Install script detected");
  }

  // 3. MAINTAINER & ACTIVITY ANALYSIS
  const maintainers = Array.isArray(pkgData.maintainers)
    ? pkgData.maintainers.length
    : 0;

  if (maintainers === 0) {
    riskScore += 25; // No maintainers = abandoned package
    reasons.push("No active maintainers");
  } else if (maintainers === 1) {
    riskScore += 15; // Single point of failure
    reasons.push("Single maintainer (single point of failure)");
  } else if (maintainers === 2) {
    riskScore += 8; // Two maintainers still lacks redundancy
    reasons.push("Limited maintainer team");
  } else if (maintainers >= 5) {
    riskScore -= 10; // Multiple maintainers significantly reduces risk
    reasons.push("Well-maintained package (multiple maintainers)");
  } else if (maintainers >= 3) {
    riskScore -= 5; // Moderate team
    reasons.push("Moderate maintainer team");
  }

  // 4. PUBLISH & ACTIVITY - Recent versions and stale packages are both risks
  const latestVersion = pkgData.time?.[pkgData.version];
  if (latestVersion) {
    const daysOld =
      (Date.now() - new Date(latestVersion)) / (1000 * 60 * 60 * 24);
    if (daysOld < 7) {
      riskScore += 12; // Recently published - supply chain risk
      reasons.push("Published <7 days ago (supply chain risk)");
    } else if (daysOld > 730) {
      riskScore += 25; // Over 2 years without updates
      reasons.push("Not updated for 2+ years (stale)");
    } else if (daysOld > 365) {
      riskScore += 18; // Over 1 year without updates
      reasons.push("Not updated for 1+ years");
    }
  }

  // 5. DOWNLOADS/POPULARITY - Inverse relationship with risk
  const downloads = pkgData.downloads || 0;

  if (downloads < 50) {
    riskScore += 18; // Essentially untested
    reasons.push("Extremely low download count (<50)");
  } else if (downloads < 500) {
    riskScore += 12; // Minimal validation
    reasons.push("Very low download count");
  } else if (downloads < 10_000) {
    riskScore += 6; // Low adoption
    reasons.push("Low download count");
  } else if (downloads > 100_000_000) {
    riskScore -= 15; // Massive adoption = heavily audited
    reasons.push("Massive adoption (100M+ downloads)");
  } else if (downloads > 10_000_000) {
    riskScore -= 12; // Very high adoption
    reasons.push("Very high adoption (10M+ downloads)");
  } else if (downloads > 1_000_000) {
    riskScore -= 8; // High adoption
    reasons.push("High adoption (1M+ downloads)");
  } else if (downloads > 100_000) {
    riskScore -= 4; // Moderate adoption
    reasons.push("Moderate adoption (100K+ downloads)");
  }

  // 6. TRANSPARENCY & DOCUMENTATION
  if (!pkgData.publisher) {
    riskScore += 4;
    reasons.push("No publisher information");
  }

  if (!pkgData.repository) {
    riskScore += 6;
    reasons.push("No repository link");
  }

  if (!pkgData.description) {
    riskScore += 3;
    reasons.push("No package description");
  }

  // ================================================
  // DETERMINE RISK LABEL & METER
  // ================================================

  const getRiskLabel = (score) => {
    if (score >= 80) return "CRITICAL RISK";
    if (score >= 50) return "HIGH RISK";
    if (score >= 20) return "MEDIUM RISK";
    return "LOW RISK";
  };

  const getRiskEmoji = (score) => {
    if (score >= 80) return "🔴"; // Critical - Red
    if (score >= 50) return "🟠"; // High - Orange
    if (score >= 20) return "🟡"; // Medium - Yellow
    return "🟢"; // Low - Green
  };

  // Clamp final score to 0-100 range
  riskScore = Math.max(0, Math.min(100, riskScore));

  const riskLabel = getRiskLabel(riskScore);
  const emoji = getRiskEmoji(riskScore);
  const status = `${emoji} ${riskLabel}`;

  // Generate risk meter visualization (20 characters)
  const meterLength = 20;
  const filledLength = Math.round((riskScore / 100) * meterLength);
  const riskMeter =
    "█".repeat(filledLength) + "░".repeat(meterLength - filledLength);

  return {
    riskScore, // 0-100 numeric score
    riskLabel, // Textual label
    status, // Emoji + Label
    riskMeter, // Visual representation [████████░░░░░░░░░░]
    reasons,
    trustScore: Math.max(0, 100 - riskScore), // Inverse score (100 = fully trustworthy)
    analysis: `${pkgData.name}: ${status} (${riskScore}/100)`,
  };
}

module.exports = { analyzeMetadata };
