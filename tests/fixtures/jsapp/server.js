const express = require("express");
const crypto = require("crypto");
const https = require("https");
const rateLimit = require("express-rate-limit");

const app = express();
app.use(rateLimit({ windowMs: 60000, max: 5 }));

const dbPassword = "supersecret42";

app.get("/api/items", (req, res) => {
  res.json([]);
});

app.post("/api/login", async (req, res) => {
  const digest = crypto.createHash("md5").update(req.body.pw).digest("hex");
  const r = await fetch(process.env.AUTH_URL, { agent: new https.Agent({ rejectUnauthorized: false }) });
  res.send(digest + r.status);
});

app.listen(process.env.PORT || 3000);
