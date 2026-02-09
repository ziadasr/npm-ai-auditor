require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const auditRoutes = require("./routes/audit");

const app = express();

app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(express.static("public"));

const rateLimit = {};
app.use("/audit", (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();

  if (!rateLimit[ip]) rateLimit[ip] = [];

  // Keep only recent requests (1 min window)
  rateLimit[ip] = rateLimit[ip].filter((time) => now - time < 60000);

  if (rateLimit[ip].length >= 100) {
    return res.status(429).json({ error: "Rate limit exceeded" });
  }

  rateLimit[ip].push(now);
  next();
});

// 🔗 ROUTES - FIXED PACKAGE HANDLING
app.use("/audit", auditRoutes);

// 🏠 ROOT REDIRECT
app.get("/", (req, res) => {
  res.redirect("/api-docs");
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`🚀 AI Package Auditor API on port ${port}`);
});
