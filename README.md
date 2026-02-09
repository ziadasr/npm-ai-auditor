# npm-ai-auditor 🔐

AI-powered npm package vulnerability scanner with Groq's Llama reasoning.

[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](LICENSE)
[![Node.js 18+](https://img.shields.io/badge/Node.js-18+-green)](https://nodejs.org)
[![Express 5](https://img.shields.io/badge/Express-5.2.1-brightgreen)](https://expressjs.com)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen)]()
[![Coverage](https://img.shields.io/badge/Coverage-In%20Progress-blue)]()
[![GitHub Stars](https://img.shields.io/github/stars/ziadasr/npm-ai-auditor?style=flat)]()

---

## 🧠 Why This Exists

- **npm audit lacks contextual exploit reasoning** - It lists CVEs but doesn't explain attack vectors and doesnt even explain what this cve is
- **Most tools are static** - They show vulns but don't reason about real-world exploitability
- **This project combines deterministic CVE data with LLM reasoning** - For contextual, explainable risk analysis

---

## ⚡ Quickstart

**1. Clone & Install:**

```bash
git clone https://github.com/ziadasr/npm-ai-auditor.git
cd npm-ai-auditor
npm install
```

**2. Set up environment** (2 free API keys):

```bash
cp .env.example .env
# Edit .env with your keys:
# - GROQ_API_KEY from https://console.groq.com
# - GITHUB_TOKEN from https://github.com/settings/tokens
```

**3. Start the server:**

```bash
npm run dev
# Server runs on http://localhost:3000
```

**4. Audit a package** (in another terminal):

```bash
# Linux/macOS
curl -X POST http://localhost:3000/audit/lodash/4.17.15

# Windows PowerShell
irm http://localhost:3000/audit/lodash/4.17.15 -Method POST
```

---

## 🎯 What It Does

Analyzes npm packages using:

- **CVE Detection** - GitHub Advisories + OSV.dev (Google's vulnerability database)
- **AI Reasoning** - Groq Llama 3.3-70B language model
- **Risk Scoring** - Industry-standard 0-100 scale with weighted factors
- **Exploit Scenarios** - LLM-generated contextual attack paths
- **Install Script Analysis** - Detects suspicious postinstall/preinstall hooks
- **Maintainer Risk Assessment** - Single-point-of-failure detection

Example: Audit `lodash@4.17.15` → Finds 4 CVEs (2 HIGH severity) → Scores 43/100 (MEDIUM RISK) due to high adoption (102M+ downloads) offsetting vulnerabilities → AI explains ReDoS/Command Injection attack vectors → Recommends upgrade to ≥4.17.21.

---

## 🏗️ Tech Stack

From `package.json`:

| Component        | Package                     | Version |
| ---------------- | --------------------------- | ------- |
| **Web Server**   | Express                     | 5.2.1   |
| **Security**     | Helmet                      | 8.1.0   |
| **CORS**         | cors                        | 2.8.6   |
| **Config**       | dotenv                      | 17.2.4  |
| **HTTP Client**  | axios                       | 1.13.4  |
| **AI Inference** | groq-sdk                    | 0.37.0  |
| **CVE Sources**  | GitHub Advisories + OSV.dev | (APIs)  |
| **Dev**          | nodemon                     | 3.1.11  |

---

## 📡 How To use

**Linux/macOS (curl):**

```bash
# Audit latest version
POST /audit/express
curl -X POST http://localhost:3000/audit/express

# Audit specific version
POST /audit/lodash/4.17.15
curl -X POST http://localhost:3000/audit/lodash/4.17.15

# Scoped packages
POST /audit/@angular/core/17.0.0
curl -X POST http://localhost:3000/audit/@angular/core/17.0.0
```

**Windows PowerShell (irm):**

```powershell
# Audit latest version
irm http://localhost:3000/audit/express -Method POST

# Audit specific version
irm http://localhost:3000/audit/lodash/4.17.15 -Method POST

# Scoped packages
irm http://localhost:3000/audit/@angular/core/17.0.0 -Method POST
```

---

## 📊 Response Example

```bash
curl -X POST http://localhost:3000/audit/lodash/4.17.15
```

### Server Console Output

When you make a request, the server terminal displays a formatted analysis:

```
🔍 AI SECURITY ANALYSIS: lodash@4.17.15
══════════════════════════════════════════════════════════════════════

📝 SUMMARY
──────────────────────────────────────────────────────────────────────
The lodash@4.17.15 package has several known vulnerabilities, including
Regular Expression Denial of Service (ReDoS), Command Injection, and
Prototype Pollution, which can be exploited to cause denial of service
or execute arbitrary code.

⚠️  RISK ASSESSMENT
──────────────────────────────────────────────────────────────────────
Risk Level:       🟡 MEDIUM RISK
Risk Score:       43/100
Risk Meter:       [█████████░░░░░░░░░░░]
Version Affected: ❌ YES

📋 RISK CRITERIA
──────────────────────────────────────────────────────────────────────
Score Ranges (Higher Score = More Dangerous):
  🟢 0-19:    LOW RISK       - Safe to use
  🟡 20-49:   MEDIUM RISK    - Review before using
  🟠 50-79:   HIGH RISK      - Careful consideration required
  🔴 80-100:  CRITICAL RISK  - Not recommended

Calculation Method (Multiplicative with Logarithmic Smoothing):
  Risk = log₂(multiplier) × 20 + 10

  Multiplier Weights by Factor:
  • Scripts: postinstall (×2.2), preinstall (×1.6), install (×1.3)
  • Maintainers: 0 (×2.8), 1 (×1.9), 2 (×1.35), 3+ (×0.82), 5+ (×0.65)
  • Package Age: <7 days (×1.45), >2 years (×1.7), >1 year (×1.35)
  • Downloads: <50 (×2.1), <500 (×1.7), <10k (×1.25), >100M (×0.45)
  • Transparency: no publisher (×1.18), no repo (×1.25), no description (×1.12)

  CVE severity scoring is handled separately in the audit route
  you can freely change the factors or the calculation way to match you from metadataAnalyzer.js

🔐 KNOWN VULNERABILITIES (CVEs)
──────────────────────────────────────────────────────────────────────
• GHSA-29mw-wpgm-hmr9 [🟢 MODERATE]
  Regular Expression Denial of Service (ReDoS) in lodash
• GHSA-35jh-r3h4-6jhm [🟠 HIGH]
  Command Injection in lodash
• GHSA-p6mc-m468-83gw [🟠 HIGH]
  Prototype Pollution in lodash
• GHSA-xxjr-mmjv-4gpg [🟢 MODERATE]
  Lodash has Prototype Pollution Vulnerability in `_.unset` and `_.omit` functions

📊 PACKAGE METADATA
──────────────────────────────────────────────────────────────────────
Downloads:   102,575,328
Publisher:   jdalton
License:     MIT
Maintainers: 2
Repository:  https://github.com/lodash/lodash

Scripts:
  test: echo "See https://travis-ci.org/lodash-archive/lodash-cli for testing details."

🛠️  SCRIPT SAFETY
──────────────────────────────────────────────────────────────────────
Suspicious Scripts: ✅ NO
The install scripts are null, indicating no custom scripts are run during
installation, reducing the risk of suspicious behavior.

⚡ EXPLOIT SCENARIO
──────────────────────────────────────────────────────────────────────
An attacker could exploit the ReDoS vulnerability by crafting a malicious
input to the `toNumber`, `trim`, or `trimEnd` functions, causing the
application to hang or crash. Alternatively, an attacker could exploit
the Command Injection vulnerability by injecting malicious commands via
the template function, potentially leading to arbitrary code execution.

💡 RECOMMENDATIONS
──────────────────────────────────────────────────────────────────────
1. Update to the latest version of lodash (>= 4.17.21) to fix the known
   vulnerabilities.
2. Implement input validation and sanitization to prevent malicious inputs
   from reaching the vulnerable functions.
3. Monitor application logs for signs of exploitation attempts.

══════════════════════════════════════════════════════════════════
```

### Client JSON Response

The API also returns structured JSON for programmatic use:

```json
{
  "success": true,
  "timestamp": "2026-02-09T22:30:00.000Z",
  "package": "lodash",
  "version": "4.17.15",
  "riskScore": 43,
  "riskStatus": "🟡 MEDIUM RISK",
  "trustScore": 57,
  "analysis": "🟡 MEDIUM RISK (43/100)",
  "cveCount": 4,
  "cves": [
    {
      "id": "GHSA-29mw-wpgm-hmr9",
      "severity": "MODERATE",
      "title": "Regular Expression Denial of Service (ReDoS) in lodash",
      "url": "https://github.com/advisories/GHSA-29mw-wpgm-hmr9"
    },
    {
      "id": "GHSA-35jh-r3h4-6jhm",
      "severity": "HIGH",
      "title": "Command Injection in lodash",
      "url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm"
    },
    {
      "id": "GHSA-p6mc-m468-83gw",
      "severity": "HIGH",
      "title": "Prototype Pollution in lodash",
      "url": "https://github.com/advisories/GHSA-p6mc-m468-83gw"
    },
    {
      "id": "GHSA-xxjr-mmjv-4gpg",
      "severity": "MODERATE",
      "title": "Lodash has Prototype Pollution Vulnerability in `_.unset` and `_.omit`",
      "url": "https://github.com/advisories/GHSA-xxjr-mmjv-4gpg"
    }
  ],
  "metadata": {
    "downloads": 102575328,
    "publisher": "jdalton",
    "license": "MIT",
    "maintainers": 2,
    "repository": "https://github.com/lodash/lodash",
    "scripts": {
      "test": "echo \"See https://travis-ci.org/lodash-archive/lodash-cli for testing details.\""
    }
  },
  "aiAnalysis": {
    "summary": "The lodash@4.17.15 package has several known vulnerabilities, including Regular Expression Denial of Service (ReDoS), Command Injection, and Prototype Pollution, which can be exploited to cause denial of service or execute arbitrary code.",
    "isVersionLikelyAffected": true,
    "scriptRisk": {
      "suspicious": false,
      "reason": "The install scripts are null, indicating no custom scripts are run during installation, reducing the risk of suspicious behavior."
    },
    "exploitScenario": "An attacker could exploit the ReDoS vulnerability by crafting a malicious input to the `toNumber`, `trim`, or `trimEnd` functions, causing the application to hang or crash. Alternatively, an attacker could exploit the Command Injection vulnerability by injecting malicious commands via the template function, potentially leading to arbitrary code execution.",
    "recommendations": [
      "Update to the latest version of lodash (>= 4.17.21) to fix the known vulnerabilities.",
      "Implement input validation and sanitization to prevent malicious inputs from reaching the vulnerable functions.",
      "Monitor application logs for signs of exploitation attempts."
    ],
    "contextualRisk": "CRITICAL"
  },
  "source": ["metadata", "github", "osv.dev", "groq-ai"]
}
```

---

## 🛠️ Installation

### Prerequisites

- Node.js 18+
- npm or yarn
- Groq API key (free from https://console.groq.com)

### Setup

```bash
# 1. Clone and enter directory
git clone https://github.com/ziadasr/npm-ai-auditor
cd npm-ai-auditor

# 2. Install dependencies
npm install

# 3. Create .env file
cp .env.example .env
# Edit .env and add your API keys:
# GITHUB_TOKEN=your_github_token_here
# GROQ_API_KEY=your_groq_api_key_here

# 4. Start server
npm run dev        # Development (with hot reload)
```

---

## 🔒 Features Implemented

✅ **CVE Detection** - GitHub Advisories + OSV.dev vulnerability databases  
✅ **AI Security Analysis** - Groq's Llama 3.3-70B analyzes context  
✅ **Exploit Scenarios** - AI generates realistic attack paths  
✅ **Install Script Analysis** - Checks preinstall/postinstall hooks  
✅ **Risk Scoring** - 0-100 scale based on metadata & CVEs  
✅ **Rate Limiting** - 100 req/min per IP  
✅ **Security Headers** - Helmet.js CSP protection  
✅ **CORS** - Cross-origin resource sharing enabled  
✅ **Timeout Protection** - 30 second max per request

---

## 📈 Comparison with Other Tools

| Feature                   | npm audit | Snyk | npm-ai-auditor  |
| ------------------------- | --------- | ---- | --------------- |
| **CVE Detection**         | ✅        | ✅   | ✅              |
| **AI-Powered Analysis**   | ❌        | ❌   | ✅ Groq LLM     |
| **Exploit Scenarios**     | ❌        | ❌   | ✅ AI-generated |
| **Version-Specific**      | ❌        | ⚠️   | ✅ Precise      |
| **Script Risk Detection** | ❌        | ⚠️   | ✅ Deep check   |
| **Free Forever**          | ✅        | ❌   | ✅              |
| **Self-Hosted**           | ✅        | ❌   | ✅              |
| **Open Source**           | ✅        | ❌   | ✅              |

---

## ⚙️ Configuration

Environment variables in `.env` (copy from `.env.example`):

```bash
# REQUIRED
GITHUB_TOKEN=xxxxxxxxxxxx               # GitHub Personal Access Token for getting CVE data
GROQ_API_KEY=gsk_xxxxxxxxxx            # Get free key from console.groq.com

# OPTIONAL
PORT=3000                               # Server port (default: 3000)
```

---

## ⚠️ Security Disclaimer

**This tool is for educational and risk-awareness purposes.**

It does not replace professional security auditing. Use this for:

- ✅ Initial vulnerability screening
- ✅ Understanding dependency risk
- ✅ Educational purposes
- ❌ NOT sole basis for security decisions in production

**Always verify findings with a security professional before making production changes.**

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch: `git checkout -b feat/your-feature`
3. Make changes and test: `npm run dev`
4. Commit: `git commit -m "feat: add your feature"`
5. Push: `git push origin feat/your-feature`
6. Submit a Pull Request

**Areas for contribution:**

- Bug fixes
- Feature implementations
- Test improvements
- Documentation
- GitHub Actions examples
- Performance optimizations

---

## ❓ FAQ

**Q: How do I get a Groq API key?**  
A: Visit https://console.groq.com, sign up (free), create an API key. Free tier: 20 requests/month.

**Q: How do I get a GitHub Personal Access Token?**  
A: Visit https://github.com/settings/tokens, click "Generate new token", select scopes (read public repositories), copy the token. Free tier: Unlimited requests for public repos.

**Q: Does it work offline?**  
A: No. CVE detection and AI analysis require internet connectivity.

**Q: Is the AI analysis always accurate?**  
A: AI provides context-aware analysis, but shouldn't be the only decision factor for critical security. Always verify important findings.

**Q: What data is sent to Groq?**  
A: Package metadata, CVE list, and version info. No source code or secrets are transmitted.

**Q: What are the rate limits for Groq API?**  
A: Free tier allows 20 requests/month (as of Feb 2025). For heavier usage:

**Q: What are the GitHub API rate limits?**  
A: Unauthenticated: 60 requests/hour. Authenticated (with token): 5,000 requests/hour. CVE lookups use ~1-3 requests per audit, so heavy users (100+ audits/day) should monitor usage.

---

## 📞 Support

- **GitHub Issues**: [Report bugs](https://github.com/ziadasr/npm-ai-auditor/issues)
- **Discussions**: [Ask questions](https://github.com/ziadasr/npm-ai-auditor/discussions)

---

## 📜 License

ISC License - See [LICENSE](LICENSE) for details

---

## 🌟 Show Your Support

If this tool helped you find vulnerabilities → **[⭐ Star this repo!](https://github.com/ziadasr/npm-ai-auditor)**

---

<div align="center">

[🐛 Issues](https://github.com/ziadasr/npm-ai-auditor/issues) | [💡 Discussions](https://github.com/ziadasr/npm-ai-auditor/discussions)

</div>
