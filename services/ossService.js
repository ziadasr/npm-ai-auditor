require("dotenv").config();
const axios = require("axios");

async function checkCVEs(pkg, version) {
  try {
    console.log(`\n🔍 Checking ${pkg}@${version}`);

    const headers = {
      "User-Agent": "ai-package-auditor",
      Accept: "application/vnd.github+json",
    };

    // Add GitHub token if available to avoid rate limiting
    if (process.env.GITHUB_TOKEN) {
      headers.Authorization = `token ${process.env.GITHUB_TOKEN}`;
      console.log(`   🔐 Using GitHub token for authentication`);
      console.log("token:", process.env.GITHUB_TOKEN);
    }

    // PARALLEL: GitHub + NEW OSV.dev
    console.log(`   📡 Calling GitHub Advisories API...`);
    console.log(`   📡 Calling OSV.dev API...`);

    const [githubResponse, osvResponse] = await Promise.all([
      // YOUR EXISTING GitHub call - UNCHANGED
      axios.get(
        `https://api.github.com/advisories?ecosystem=npm&q=${pkg}+${version}`,
        { headers, timeout: 10000 },
      ),

      // OSV.dev (Google vulnerability DB)
      axios.post(
        "https://api.osv.dev/v1/query",
        {
          package: { name: pkg, ecosystem: "npm" },
          version: version,
        },
        {
          headers: { "Content-Type": "application/json" },
          timeout: 8000,
        },
      ),
    ]);

    // GitHub Response
    console.log(`   ✓ GitHub API Status: ${githubResponse.status}`);
    const advisories = Array.isArray(githubResponse.data)
      ? githubResponse.data
      : [];
    console.log(`   ✓ GitHub Response items: ${advisories.length}`);
    if (advisories.length > 0) {
      console.log(`   📋 Sample GitHub response structure:`);
      console.log(`      Keys: ${Object.keys(advisories[0]).join(", ")}`);
    }

    let debugGH = false;
    const relevantAdvisories = advisories.filter((advisory) => {
      const pkgName = pkg.replace(/@.*\//, "");

      // Check if any vulnerability in this advisory affects our package
      const hasRelevant = advisory.vulnerabilities?.some((vuln) => {
        if (!debugGH && advisory.ghsa_id?.includes("GHSA-vh95")) {
          console.log(`   🔍 DEBUG minimist advisory:`);
          console.log(`      Advisory: ${advisory.ghsa_id}`);
          console.log(
            `      Vuln packages: ${advisory.vulnerabilities?.map((v) => v.package?.name).join(", ")}`,
          );
          debugGH = true;
        }

        // Check if vuln has package name field
        return vuln.package?.name
          ?.toLowerCase()
          .includes(pkgName.toLowerCase());
      });

      return hasRelevant;
    });
    console.log(
      `   ✓ GitHub Relevant advisories: ${relevantAdvisories.length}`,
    );

    const githubCVEs = relevantAdvisories
      .map((advisory) => ({
        id: advisory.ghsa_id || advisory.cve_id || "unknown",
        title: advisory.summary,
        severity: advisory.severity?.toUpperCase() || "UNKNOWN",
        description: advisory.summary.substring(0, 200) + "...",
        url: advisory.html_url,
        published: advisory.published_at,
        source: "github", //  source tag
        vulnerableVersions:
          advisory.vulnerabilities
            ?.filter((v) =>
              v.package.name
                .toLowerCase()
                .includes(pkg.replace(/@.*\//, "").toLowerCase()),
            )
            ?.map((v) => v.vulnerable_version_range) || [],
      }))
      .filter((cve) => cve.id !== "unknown");

    console.log(`   ✓ GitHub CVEs parsed: ${githubCVEs.length}`);

    // OSV.dev Response
    console.log(`   ✓ OSV.dev API Status: ${osvResponse.status}`);
    const osvVulns = osvResponse.data.vulns || [];
    console.log(`   ✓ OSV.dev Response vulnerabilities: ${osvVulns.length}`);
    if (osvVulns.length > 0) {
      console.log(`   📋 Sample OSV.dev response structure:`);
      console.log(`      Keys: ${Object.keys(osvVulns[0]).join(", ")}`);
    }

    const osvCVEs = osvVulns.map((vuln) => ({
      id: vuln.id,
      title: vuln.summary || `Vulnerability ${vuln.id}`,
      severity:
        (typeof vuln.severity === "string"
          ? vuln.severity
          : vuln.database_specific?.severity) || "UNKNOWN",
      description:
        (vuln.details || vuln.summary || "").substring(0, 200) + "...",
      url: vuln.id.startsWith("GHSA-")
        ? `https://github.com/advisories/${vuln.id}`
        : `https://osv.dev/${vuln.id}`,
      published: vuln.published || vuln.modified,
      source: "osv.dev",
      vulnerableVersions:
        vuln.affected?.map((a) => a.ranges?.[0]?.events || [a.version]) || [],
    }));

    console.log(`   ✓ OSV.dev CVEs parsed: ${osvCVEs.length}`);

    // 3. 🆕 COMBINE + DEDUPLICATE
    const allCVEs = [...githubCVEs, ...osvCVEs];
    console.log(`   ✓ Combined CVEs: ${allCVEs.length}`);

    const uniqueCVEs = allCVEs.filter(
      (cve, index, self) =>
        index === self.findIndex((item) => item.id === cve.id),
    );

    console.log(`   ✓ Deduplicated CVEs: ${uniqueCVEs.length}`);
    console.log(
      `   📊 FINAL RESULT: ${uniqueCVEs.length} TOTAL CVEs (${githubCVEs.length} GitHub + ${osvCVEs.length} OSV)\n`,
    );

    return uniqueCVEs;
  } catch (error) {
    console.log(`\n❌ Error checking ${pkg}@${version}:`);

    if (error.response) {
      console.log(`   Status Code: ${error.response.status}`);
      console.log(`   Status Text: ${error.response.statusText}`);
      if (error.response.status === 401) {
        console.log(`   ⚠️  UNAUTHORIZED - API request rejected`);
      } else if (error.response.status === 403) {
        console.log(`   ⚠️  FORBIDDEN - Rate limited or permission denied`);
      } else if (error.response.status === 404) {
        console.log(`   ⚠️  NOT FOUND - Package may not exist`);
      }
      console.log(
        `   Response: ${error.response.data?.message || error.response.statusText}`,
      );
    } else if (error.code === "ECONNREFUSED") {
      console.log(`   ⚠️  CONNECTION REFUSED - API unreachable`);
    } else if (error.code === "ETIMEDOUT") {
      console.log(`   ⚠️  TIMEOUT - API took too long to respond`);
    } else {
      console.log(`   Error: ${error.message}`);
    }
    console.log(`\n`);

    return [];
  }
}

module.exports = { checkCVEs };

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-
// const axios = require("axios");

// async function checkCVEs(pkg, version) {
//   try {
//     console.log(`🔍 Checking ${pkg}@${version}`);

//     const headers = {
//       "User-Agent": "ai-package-auditor",
//       Accept: "application/vnd.github+json",
//     };

//     // Add GitHub token if available to avoid rate limiting
//     if (process.env.GITHUB_TOKEN) {
//       headers.Authorization = `token ${process.env.GITHUB_TOKEN}`;
//     }

//     const response = await axios.get(
//       `https://api.github.com/advisories?ecosystem=npm&q=${pkg}+${version}`,
//       {
//         headers,
//         timeout: 10000,
//       },
//     );

//     const advisories = Array.isArray(response.data) ? response.data : [];
//     const relevantAdvisories = advisories.filter((advisory) => {
//       const pkgName = pkg.replace(/@.*\//, ""); // express, not @scope/express
//       return advisory.vulnerabilities?.some((vuln) =>
//         vuln.package.name.toLowerCase().includes(pkgName.toLowerCase()),
//       );
//     });

//     console.log(
//       `📊 ${relevantAdvisories.length} RELEVANT CVEs for ${pkg}@${version}`,
//     );

//     return (
//       relevantAdvisories
//         .map((advisory) => ({
//           id: advisory.ghsa_id || advisory.cve_id || "unknown",
//           title: advisory.summary,
//           severity: advisory.severity?.toUpperCase() || "UNKNOWN",
//           description: advisory.summary.substring(0, 200) + "...",
//           url: advisory.html_url,
//           published: advisory.published_at,
//           vulnerableVersions:
//             advisory.vulnerabilities
//               ?.filter((v) =>
//                 v.package.name
//                   .toLowerCase()
//                   .includes(pkg.replace(/@.*\//, "").toLowerCase()),
//               )
//               ?.map((v) => v.vulnerable_version_range) || [],
//         }))
//         ?.filter((cve) => cve.id !== "unknown") || []
//     );
//   } catch (error) {
//     console.log(
//       `⚠️ Error ${pkg}@${version}:`,
//       error.response?.status || error.message,
//     );
//     return [];
//   }
// }

module.exports = { checkCVEs };
