// services/aiService.js
require("dotenv").config();
const Groq = require("groq-sdk");

console.log("✅ aiService.js loaded");
console.log("🔑 GROQ_API_KEY exists:", !!process.env.GROQ_API_KEY);
console.log("🔑 GROQ_API_KEY length:", process.env.GROQ_API_KEY?.length);

const groq = new Groq({
  apiKey: process.env.GROQ_API_KEY,
});

console.log("✅ Groq client initialized");

/**
 * Sleep helper (for retry delay)
 */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Safely parse JSON returned by LLM
 */
function safeJSONParse(text) {
  console.log("🔍 Attempting to parse JSON...");
  try {
    if (!text) {
      console.log("⚠️  Text is empty or null");
      return null;
    }

    console.log("📝 Original text length:", text.length);

    const cleaned = text
      .replace(/```json/gi, "")
      .replace(/```/g, "")
      .trim();

    console.log("📝 Cleaned text length:", cleaned.length);
    console.log("📝 Cleaned preview:", cleaned.substring(0, 100));

    const result = JSON.parse(cleaned);
    console.log("✅ JSON parse successful");
    return result;
  } catch (err) {
    console.error("❌ Failed to parse AI JSON:", err.message);
    console.error("Error details:", err);
    return null;
  }
}

/**
 * AI Security Context Reasoning Layer
 */
async function analyzeSecurityContext({
  packageName,
  version,
  metadata = {},
  cves = [],
  scripts = {},
  riskScore = 0,
  historicalNote = null,
}) {
  console.log("\n🤖 ========== AI ANALYSIS START ==========");
  console.log("📦 Package:", packageName + "@" + version);
  console.log("⚠️  CVE Count:", cves.length);
  console.log("📊 Risk Score:", riskScore);
  console.log("🛠️  Scripts:", Object.keys(scripts).join(", ") || "none");

  const fallback = {
    summary: "AI analysis unavailable.",
    contextualRisk: "UNKNOWN",
  };

  const prompt = `
You are a senior application security engineer.

Analyze this npm package security context professionally and realistically.

Package: ${packageName}@${version}
Current Calculated Risk Score: ${riskScore}/100

-------------------------------------
METADATA
-------------------------------------
Downloads: ${metadata.downloads || "unknown"}
Maintainers: ${metadata.maintainers || "unknown"}
Publisher: ${metadata.publisher || "unknown"}
License: ${metadata.license || "unknown"}

-------------------------------------
INSTALL SCRIPTS
-------------------------------------
${JSON.stringify(
  {
    preinstall: scripts.preinstall || null,
    install: scripts.install || null,
    postinstall: scripts.postinstall || null,
  },
  null,
  2,
)}

-------------------------------------
KNOWN VULNERABILITIES
-------------------------------------
${JSON.stringify(cves, null, 2)}

-------------------------------------
HISTORICAL CONTEXT
-------------------------------------
${historicalNote || "None"}

-------------------------------------

Tasks:

1. Explain vulnerabilities clearly.
2. Determine if this specific version is likely affected.
3. Evaluate install scripts for suspicious behavior.
4. Provide realistic exploit scenario (if applicable).
5. Give actionable recommendations.
6. Classify contextual risk: LOW / MEDIUM / HIGH / CRITICAL.

Be balanced. Do not exaggerate.

Respond with JSON ONLY in this format:

{
  "summary": "short explanation",
  "isVersionLikelyAffected": true,
  "scriptRisk": {
    "suspicious": false,
    "reason": "explanation"
  },
  "exploitScenario": "realistic scenario or null",
  "recommendations": ["recommendation 1"],
  "contextualRisk": "LOW"
}
`;

  let retries = 2;

  while (retries--) {
    try {
      console.log(`\n🔄 API Call Attempt (${3 - retries}/3)...`);
      console.log("📝 Prompt length:", prompt.length);
      console.log("🚀 Model:", "llama-3.3-70b-versatile");

      const response = await groq.chat.completions.create({
        messages: [{ role: "user", content: prompt }],
        model: "llama-3.3-70b-versatile",
        temperature: 0.2,
        max_tokens: 1000,
      });

      console.log("✅ API Response received");
      console.log("📋 Response keys:", Object.keys(response).join(", "));
      console.log("🔗 Choices length:", response.choices?.length);

      const content = response.choices?.[0]?.message?.content;
      console.log("📄 Content length:", content?.length);
      console.log("📄 Content preview:", content?.substring(0, 100));

      const parsed = safeJSONParse(content);

      if (!parsed) {
        console.error("❌ JSON parsing returned null");
        throw new Error("Invalid JSON from AI");
      }

      console.log("✅ JSON parsed successfully");
      console.log("🎯 Parsed keys:", Object.keys(parsed).join(", "));
      console.log("✅ ========== AI ANALYSIS COMPLETE ==========\n");
      return parsed;
    } catch (error) {
      console.error(`\n❌ AI attempt failed (${3 - retries}/3)`);
      console.error("Error name:", error.name);
      console.error("Error message:", error.message);
      console.error("Error code:", error.code);
      console.error("Error status:", error.status);
      console.error("Full error:", error);

      if (retries === 0) {
        console.error("❌ All AI retries failed for:", packageName);
        console.log("📦 Returning fallback response");
        console.log("❌ ========== AI ANALYSIS FAILED ==========\n");
        return fallback;
      }

      console.log(`⏳ Waiting 1 second before retry...`);
      await sleep(1000);
    }
  }

  return fallback;
}

module.exports = { analyzeSecurityContext };
