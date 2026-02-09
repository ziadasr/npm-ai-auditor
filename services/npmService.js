// services/npmService.js
const axios = require("axios");
async function getPackageData(pkg, version = "latest") {
  try {
    const [pkgRes, statsRes] = await Promise.all([
      // Fetch package metadata from npm registry
      axios.get(`https://registry.npmjs.org/${pkg}/${version}`),
      //get 7-day download stats for popularity check
      axios.get(`https://api.npmjs.org/downloads/point/last-week/${pkg}`),
    ]);
    const pkgData = pkgRes.data;

    return {
      //  CRITICAL SECURITY FIELDS
      name: pkgData.name,
      version: pkgData.version,

      // 1. DOWNLOADS (Popularity check)
      downloads: statsRes.data.downloads || 0,

      // 2. SCRIPTS (Postinstall attacks)
      scripts: pkgData.scripts || {},

      // 3. DEPENDENCIES (Transitive risks)
      dependencies: pkgData.dependencies || {},
      devDependencies: pkgData.devDependencies || {},

      // 4. PUBLISHER (Account hijacking)
      publisher: pkgData.publisher || null,

      // 5. REPOSITORY (Trust verification)
      repository: pkgData.repository || null,

      // 6. PUBLISH TIME (Freshness check)
      time: pkgData.time || {},

      // 7. MAINTAINERS (Team size/trust)
      maintainers: pkgData.maintainers || [],

      // 8. LICENSE (Compliance)
      license: pkgData.license || "UNKNOWN",

      // 9. KEYWORDS (Category analysis)
      keywords: pkgData.keywords || [],
    };
  } catch (error) {
    throw new Error(`Package not found: ${pkg}@${version}`);
  }
}

module.exports = { getPackageData };
