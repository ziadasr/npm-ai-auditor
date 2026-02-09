const npmService = require("./npmService");
const ossService = require("./ossService");
const { analyzeMetadata } = require("./metadataAnalyzer");

async function auditPackage(pkg, version = "latest") {
  const [pkgData, cves] = await Promise.all([
    npmService.getPackageData(pkg, version),
    ossService.checkCVEs(pkg, version),
  ]);

  const metadataAnalysis = await analyzeMetadata(pkgData);

  return {
    success: true,
    package: pkgData.name,
    version: pkgData.version,
    cveCount: cves.length,
    cves: cves,
    metadata: pkgData,
    riskScore: metadataAnalysis.riskScore,
    riskStatus: metadataAnalysis.status,
    trustScore: metadataAnalysis.trustScore,
    riskReasons: metadataAnalysis.reasons,
    analysis: metadataAnalysis.analysis,
    source: "metadata+github",
  };
}

module.exports = { auditPackage };
