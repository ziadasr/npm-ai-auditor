// services/patternService.js
const SAFE_PATTERNS = {
  "^express(@.*)?$": { cveCount: 0, status: "🟢 SAFE - Core web framework" },
  "^react(@.*)?$": { cveCount: 0, status: "🟢 SAFE - Facebook maintained" },
  "^lodash(@.*)?$": { cveCount: 0, status: "🟢 SAFE - All CVEs fixed" },
  "^axios(@.*)?$": { cveCount: 0, status: "🟢 SAFE - HTTP leader" },
};

const DANGER_PATTERNS = {
  sandboxjs: { cveCount: 4, status: "🔴 DANGER - Multiple RCEs" },
  flat: { cveCount: 2, status: "🔴 DANGER - Supply chain attack" },
};

async function analyzeByPattern(pkg) {
  // Check SAFE patterns
  for (const [pattern, result] of Object.entries(SAFE_PATTERNS)) {
    if (new RegExp(pattern).test(pkg)) {
      return { ...result, source: "pattern", package: pkg };
    }
  }

  // Check DANGER patterns
  for (const [pattern, result] of Object.entries(DANGER_PATTERNS)) {
    if (pkg.includes(pattern)) {
      return { ...result, source: "pattern-danger", package: pkg };
    }
  }

  return null; // No pattern match
}

module.exports = { analyzeByPattern };
