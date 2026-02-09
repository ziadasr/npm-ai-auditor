const express = require("express");
const { auditPackage } = require("../services/packageAuditor");
const { analyzeSecurityContext } = require("../services/aiService");

const router = express.Router();

/* =========================
   Risk Calculation (Industry Standard)
   Higher Score = More Dangerous (0-100)
========================= */

/**
 * Calculate comprehensive risk score based on CVE severity, maintainers,
 * downloads popularity, and install scripts
 *
 * Score Ranges:
 *   0-19:   LOW RISK      (safe)
 *   20-49:  MEDIUM RISK   (review before using)
 *   50-79:  HIGH RISK     (careful consideration required)
 *   80-100: CRITICAL RISK (not recommended)
 */
const calculateRiskScore = (result) => {
  let score = 0;
  const cveCount = result.cveCount || 0;
  const cves = result.cves || [];
  const metadata = result.metadata || {};

  // ================================================
  // 1. CVE SEVERITY (Highest Impact Factor)
  // ================================================
  let criticalCount = 0;
  let highCount = 0;

  cves.forEach((cve) => {
    const severity = cve.severity ? cve.severity.toUpperCase() : "";
    if (severity === "CRITICAL") {
      criticalCount++;
      score += 35; // Each CRITICAL CVE immediately increases risk substantially
    } else if (severity === "HIGH") {
      highCount++;
      score += 15; // HIGH severity has significant impact
    } else if (severity === "MEDIUM") {
      score += 5; // MEDIUM severity has minor contribution
    } else if (cveCount > 0) {
      score += 8; // Unknown severity still counted
    }
  });

  // ================================================
  // 2. MAINTAINER COUNT & ACTIVITY (Single Point of Failure)
  // ================================================
  const maintainers = Array.isArray(metadata.maintainers)
    ? metadata.maintainers.length
    : Number(metadata.maintainers || 0);

  if (maintainers === 0) {
    score += 25; // No maintainers = abandoned package risk
  } else if (maintainers === 1) {
    score += 15; // Single maintainer = significant bottleneck risk
  } else if (maintainers === 2) {
    score += 8; // Two maintainers still lacks redundancy
  } else if (maintainers >= 5) {
    score -= 10; // Multiple maintainers = strong risk reduction
  } else if (maintainers >= 3) {
    score -= 5; // Moderate team = some risk reduction
  }

  // ================================================
  // 3. DOWNLOADS/POPULARITY (Inverse Risk)
  // ================================================
  const downloads = metadata.downloads || 0;

  if (downloads < 50) {
    score += 18; // Essentially untested package
  } else if (downloads < 500) {
    score += 12; // Minimal community validation
  } else if (downloads < 10_000) {
    score += 6; // Low adoption
  } else if (downloads > 100_000_000) {
    score -= 15; // Massive adoption = heavily audited
  } else if (downloads > 10_000_000) {
    score -= 12; // Very high adoption
  } else if (downloads > 1_000_000) {
    score -= 8; // High adoption
  } else if (downloads > 100_000) {
    score -= 4; // Moderate adoption
  }

  // ================================================
  // 4. INSTALL SCRIPTS (Common Malware Vector)
  // ================================================
  if (metadata.scripts?.postinstall) {
    score += 20; // Major risk: postinstall can run arbitrary code
  }
  if (metadata.scripts?.preinstall) {
    score += 12; // Preinstall scripts are also risky
  }
  if (metadata.scripts?.install) {
    score += 8; // Install scripts add some risk
  }

  // ================================================
  // 5. PACKAGE AGE & UPDATE FREQUENCY
  // ================================================
  const latestVersion = metadata.time?.[metadata.version];
  if (latestVersion) {
    const daysOld =
      (Date.now() - new Date(latestVersion)) / (1000 * 60 * 60 * 24);
    if (daysOld < 7) {
      score += 12; // Recently published (potential account takeover)
    } else if (daysOld > 365) {
      score += 18; // Over 1 year without updates
    } else if (daysOld > 730) {
      score += 25; // Over 2 years without updates
    }
  }

  // ================================================
  // 6. TRANSPARENCY & DOCUMENTATION
  // ================================================
  if (!metadata.publisher) {
    score += 4; // Missing publisher info
  }

  if (!metadata.repository) {
    score += 6; // No repository link = reduced transparency
  }

  // Clamp final score to 0-100 range
  return Math.max(0, Math.min(100, score));
};

/**
 * Get risk status label from numeric score
 */
const getRiskStatus = (score) => {
  if (score >= 80) return "CRITICAL RISK";
  if (score >= 50) return "HIGH RISK";
  if (score >= 20) return "MEDIUM RISK";
  return "LOW RISK";
};

/**
 * Get emoji indicator for risk level
 */
const getRiskEmoji = (score) => {
  if (score >= 80) return "🔴"; // Critical - Red
  if (score >= 50) return "🟠"; // High - Orange
  if (score >= 20) return "🟡"; // Medium - Yellow
  return "🟢"; // Low - Green
};

/* =========================
   AI Analysis Console Formatter
========================= */

const formatAIAnalysisForConsole = (
  pkg,
  version,
  aiAnalysis,
  score,
  cves = [],
  metadata = {},
) => {
  // Derive risk status from score (Higher = More Dangerous)
  let riskColor = "";
  let riskStatus = "";
  if (score >= 80) {
    riskStatus = "CRITICAL RISK";
    riskColor = "🔴";
  } else if (score >= 50) {
    riskStatus = "HIGH RISK";
    riskColor = "🟠";
  } else if (score >= 20) {
    riskStatus = "MEDIUM RISK";
    riskColor = "🟡";
  } else {
    riskStatus = "LOW RISK";
    riskColor = "🟢";
  }

  // Risk meter visualization (Higher filled = More Risk)
  const meterLength = 20;
  const filledLength = Math.round((score / 100) * meterLength);
  const meter =
    "█".repeat(filledLength) + "░".repeat(meterLength - filledLength);

  console.log("\n🔍 AI SECURITY ANALYSIS: " + pkg + "@" + version);
  console.log("═".repeat(70));

  // Summary Section
  console.log("\n📝 SUMMARY");
  console.log("─".repeat(70));
  console.log(aiAnalysis.summary);

  // Risk Assessment Section
  console.log("\n⚠️  RISK ASSESSMENT");
  console.log("─".repeat(70));
  console.log(`Risk Level:       ${riskColor} ${riskStatus}`);
  console.log(`Risk Score:       ${score}/100`);
  console.log(`Risk Meter:       [${meter}]`);
  console.log(
    `Version Affected: ${aiAnalysis.isVersionLikelyAffected ? "❌ YES" : "✅ NO"}`,
  );

  // Risk Criteria Section
  console.log("\n📋 RISK CRITERIA");
  console.log("─".repeat(70));
  console.log("Score Ranges (Higher Score = More Dangerous):");
  console.log("  🟢 0-19:    LOW RISK       - Safe to use");
  console.log("  🟡 20-49:   MEDIUM RISK    - Review before using");
  console.log("  🟠 50-79:   HIGH RISK      - Careful consideration required");
  console.log("  🔴 80-100:  CRITICAL RISK  - Not recommended");
  console.log("\nCalculation Factors:");
  console.log(
    "  • CVE Severity & Count (12 pts per CVE, +15 for CRITICAL, +8 for HIGH)",
  );
  console.log("  • Maintainers count & activity (0 maintainers = +20 pts)");
  console.log("  • Download popularity (fewer downloads = higher risk)");
  console.log("  • Install scripts: postinstall (+25), preinstall (+15)");

  // CVEs Section
  if (cves && cves.length > 0) {
    console.log("\n🔐 KNOWN VULNERABILITIES (CVEs)");
    console.log("─".repeat(70));
    cves.slice(0, 5).forEach((cve, idx) => {
      const cveId = cve.id || cve.cve || `CVE-${idx + 1}`;
      const severity = cve.severity || "UNKNOWN";
      const severityEmoji =
        severity === "CRITICAL"
          ? "🔴"
          : severity === "HIGH"
            ? "🟠"
            : severity === "MEDIUM"
              ? "🟡"
              : "🟢";
      console.log(`• ${cveId} [${severityEmoji} ${severity}]`);
      if (cve.title || cve.summary) {
        console.log(`  ${cve.title || cve.summary}`);
      }
    });
    if (cves.length > 5) {
      console.log(`• ... and ${cves.length - 5} more vulnerabilities`);
    }
  }

  // Metadata Section
  if (metadata && Object.keys(metadata).length > 0) {
    console.log("\n📊 PACKAGE METADATA");
    console.log("─".repeat(70));
    if (metadata.downloads) {
      const downloads = Number(metadata.downloads).toLocaleString();
      console.log(`Downloads:   ${downloads}`);
    }
    if (metadata.publisher) {
      console.log(`Publisher:   ${metadata.publisher}`);
    }
    if (metadata.license && metadata.license !== "UNKNOWN") {
      console.log(`License:     ${metadata.license}`);
    }
    if (metadata.maintainers) {
      const maintainers = Array.isArray(metadata.maintainers)
        ? metadata.maintainers.length
        : metadata.maintainers;
      console.log(`Maintainers: ${maintainers}`);
    }
    if (metadata.repository) {
      const repo = metadata.repository
        .replace("git+", "")
        .replace(".git", "")
        .substring(0, 60);
      console.log(`Repository:  ${repo}`);
    }
    if (metadata.scripts && Object.keys(metadata.scripts).length > 0) {
      console.log("\nScripts:");
      Object.entries(metadata.scripts).forEach(([key, value]) => {
        console.log(`  ${key}: ${value}`);
      });
    }
  }

  // Script Risk Section
  console.log("\n🛠️  SCRIPT SAFETY");
  console.log("─".repeat(70));
  console.log(
    `Suspicious Scripts: ${aiAnalysis.scriptRisk?.suspicious ? "⚠️  YES" : "✅ NO"}`,
  );
  if (aiAnalysis.scriptRisk?.reason) {
    console.log(aiAnalysis.scriptRisk.reason);
  }

  // Exploit Scenario Section
  if (aiAnalysis.exploitScenario) {
    console.log("\n⚡ EXPLOIT SCENARIO");
    console.log("─".repeat(70));
    console.log(aiAnalysis.exploitScenario);
  }

  // Recommendations Section
  if (aiAnalysis.recommendations && aiAnalysis.recommendations.length > 0) {
    console.log("\n💡 RECOMMENDATIONS");
    console.log("─".repeat(70));
    aiAnalysis.recommendations.forEach((rec, idx) => {
      console.log(`${idx + 1}. ${rec}`);
    });
  }

  console.log("\n" + "═".repeat(70) + "\n");
};

/* =========================
   Main Handler
========================= */

async function handleAudit(req, res, pkg, version) {
  try {
    const finalVersion = version || req.query.version || "latest";

    // Validate package format
    if (!pkg?.match(/^(@[a-z0-9.-]+\/)?[a-z0-9.-]+$/i)) {
      return res.status(400).json({
        success: false,
        error: "Invalid package name",
      });
    }

    const result = await auditPackage(pkg, finalVersion);

    const score = calculateRiskScore(result);
    const status = getRiskStatus(score);
    const emoji = getRiskEmoji(score);

    const metadata = result.metadata || {};

    const normalizedMetadata = {
      downloads: Number(metadata.downloads || 0),

      // Publisher fallbacks
      publisher:
        metadata.publisher?.name ||
        metadata.author?.name ||
        metadata.author ||
        metadata._npmUser?.name ||
        metadata.maintainers?.[0]?.name ||
        "UNKNOWN",

      repository:
        typeof metadata.repository === "object"
          ? metadata.repository.url
          : metadata.repository || null,

      license: metadata.license || "UNKNOWN",

      maintainers: Array.isArray(metadata.maintainers)
        ? metadata.maintainers.length
        : Number(metadata.maintainers || 0),

      keywords: Array.isArray(metadata.keywords)
        ? metadata.keywords.slice(0, 10)
        : [],

      firstPublished:
        metadata.time?.created ||
        Object.values(metadata.time || {}).sort()[0] ||
        null,

      scripts: metadata.scripts || {},
    };

    // GET AI ANALYSIS
    const aiAnalysis = await analyzeSecurityContext({
      packageName: pkg,
      version: result.version || finalVersion,
      metadata: normalizedMetadata,
      cves: result.cves || [],
      scripts: metadata.scripts || {},
      riskScore: score,
      historicalNote: null,
    });

    // Format and display AI analysis in console
    formatAIAnalysisForConsole(
      pkg,
      result.version || finalVersion,
      aiAnalysis,
      score,
      result.cves || [],
      normalizedMetadata,
    );

    return res.status(200).json({
      success: true,
      timestamp: new Date().toISOString(),
      ecosystem: "npm",

      package: pkg,
      version: result.version || finalVersion,

      cveCount: result.cveCount || 0,
      cves: result.cves || [],

      metadata: normalizedMetadata,

      // Risk Assessment
      riskScore: score,
      riskStatus: status,
      trustScore: score,
      analysis: `${emoji} ${status} (${score}/100)`,

      //  AI ANALYSIS
      aiAnalysis: aiAnalysis,

      source: ["metadata", "github", "osv.dev", "groq-ai"],
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: "Audit failed",
      details: error.message,
    });
  }
}

/* =========================
   Routes
========================= */

router.post("/:pkg", (req, res) => {
  handleAudit(req, res, req.params.pkg);
});

router.post("/:pkg/:version", (req, res) => {
  handleAudit(req, res, req.params.pkg, req.params.version);
});

router.post("/@:scope/:pkg", (req, res) => {
  const pkg = `@${req.params.scope}/${req.params.pkg}`;
  handleAudit(req, res, pkg);
});

router.post("/@:scope/:pkg/:version", (req, res) => {
  const pkg = `@${req.params.scope}/${req.params.pkg}`;
  handleAudit(req, res, pkg, req.params.version);
});

module.exports = router;
