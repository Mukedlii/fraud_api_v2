import express from "express";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { createFacilitatorConfig } from "@coinbase/x402";
import { bazaarResourceServerExtension, declareDiscoveryExtension } from "@x402/extensions/bazaar";

const app = express();
app.use(express.json());

const GETIPINTEL = "https://check.getipintel.net/check.php";
const IP_API = "http://ip-api.com/json";
const ABUSEIPDB = "https://api.abuseipdb.com/api/v2/check";

const WALLET = process.env.WALLET_ADDRESS;
const CDP_KEY_ID = process.env.CDP_API_KEY_ID;
const CDP_KEY_SECRET = process.env.CDP_API_KEY_SECRET;
const CONTACT_EMAIL = process.env.CONTACT_EMAIL || "contact@example.com";
const ABUSEIPDB_KEY = process.env.ABUSEIPDB_API_KEY || "";

if (!WALLET) throw new Error("WALLET_ADDRESS env var is required");
if (!CDP_KEY_ID || !CDP_KEY_SECRET) throw new Error("CDP_API_KEY_ID and CDP_API_KEY_SECRET are required");

const facilitatorConfig = createFacilitatorConfig(CDP_KEY_ID, CDP_KEY_SECRET);
const facilitator = new HTTPFacilitatorClient(facilitatorConfig);
const resourceServer = new x402ResourceServer(facilitator)
  .register("eip155:8453", new ExactEvmScheme())
  .registerExtension(bazaarResourceServerExtension);

const makeAccepts = (price) => ({
  scheme: "exact",
  price,
  network: "eip155:8453",
  payTo: WALLET,
});

const routes = {
  "GET /score": {
    accepts: makeAccepts("$0.003"),
    description: "Multi-source IP fraud score (0-100) combining ML model + community abuse reports + VPN/proxy/TOR detection + geolocation. Ideal for fraud prevention in AI agent workflows.",
    mimeType: "application/json",
    extensions: {
      ...declareDiscoveryExtension({
        input: { ip: "8.8.8.8" },
        inputSchema: {
          properties: {
            ip: { type: "string", description: "IPv4 or IPv6 address to analyze" },
          },
          required: ["ip"],
        },
        output: {
          example: {
            ip: "8.8.8.8",
            fraudScore: 2,
            riskLevel: "safe",
            isVpnOrProxy: false,
            abuseConfidence: 0,
            totalReports: 0,
            geo: { country: "United States", city: "Ashburn", isp: "Google LLC" },
          },
        },
      }),
    },
  },
  "GET /batch": {
    accepts: makeAccepts("$0.01"),
    description: "Multi-source fraud analysis for up to 5 IP addresses in a single request. Returns combined ML + abuse report scores with geolocation.",
    mimeType: "application/json",
    extensions: {
      ...declareDiscoveryExtension({
        input: { ips: "8.8.8.8,1.1.1.1,9.9.9.9" },
        inputSchema: {
          properties: {
            ips: { type: "string", description: "Comma-separated list of up to 5 IP addresses" },
          },
          required: ["ips"],
        },
        output: {
          example: {
            count: 3,
            results: {
              "8.8.8.8": { fraudScore: 2, riskLevel: "safe", isVpnOrProxy: false },
            },
          },
        },
      }),
    },
  },
};

app.use(paymentMiddleware(routes, resourceServer));

async function getIPIntelScore(ip) {
  try {
    const url = `${GETIPINTEL}?ip=${encodeURIComponent(ip)}&contact=${encodeURIComponent(CONTACT_EMAIL)}&flags=m`;
    const res = await fetch(url, {
      headers: { "User-Agent": "IPFraudAPI/2.0" },
      signal: AbortSignal.timeout(8000),
    });
    const text = await res.text();
    const score = parseFloat(text.trim());
    return isNaN(score) || score < 0 ? null : score;
  } catch {
    return null;
  }
}

async function getAbuseScore(ip) {
  if (!ABUSEIPDB_KEY) return null;
  try {
    const url = `${ABUSEIPDB}?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`;
    const res = await fetch(url, {
      headers: { Key: ABUSEIPDB_KEY, Accept: "application/json" },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return null;
    const data = await res.json();
    return {
      abuseConfidence: data.data?.abuseConfidenceScore ?? 0,
      totalReports: data.data?.totalReports ?? 0,
      lastReported: data.data?.lastReportedAt ?? null,
      isTor: data.data?.isTor ?? false,
    };
  } catch {
    return null;
  }
}

async function getGeo(ip) {
  try {
    const fields = "status,country,countryCode,regionName,city,isp,org,timezone";
    const res = await fetch(`${IP_API}/${encodeURIComponent(ip)}?fields=${fields}`, {
      signal: AbortSignal.timeout(6000),
    });
    const data = await res.json();
    if (data.status === "fail") return null;
    return {
      country: data.country,
      countryCode: data.countryCode,
      region: data.regionName,
      city: data.city,
      isp: data.isp,
      org: data.org,
      timezone: data.timezone,
    };
  } catch {
    return null;
  }
}

function computeFraudScore(intelScore, abuseData) {
  // Combine GetIPIntel (0-1) and AbuseIPDB (0-100) into unified 0-100 score
  let score = 0;
  let sources = 0;

  if (intelScore !== null) {
    score += intelScore * 60; // weight: 60%
    sources++;
  }

  if (abuseData !== null) {
    score += (abuseData.abuseConfidence / 100) * 40; // weight: 40%
    sources++;
  }

  if (sources === 0) return null;
  if (sources === 1) score = score / (intelScore !== null ? 0.6 : 0.4);

  return Math.min(Math.round(score), 100);
}

function getRiskLevel(score) {
  if (score === null) return "unknown";
  if (score >= 90) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  if (score >= 15) return "low";
  return "safe";
}

async function analyzeIP(ip) {
  const [intelScore, abuseData, geo] = await Promise.all([
    getIPIntelScore(ip),
    getAbuseScore(ip),
    getGeo(ip),
  ]);

  const fraudScore = computeFraudScore(intelScore, abuseData);
  const riskLevel = getRiskLevel(fraudScore);

  return {
    ip,
    fraudScore,
    riskLevel,
    isVpnOrProxy: intelScore !== null ? intelScore >= 0.99 : null,
    isTor: abuseData?.isTor ?? null,
    sources: {
      getipintel: intelScore !== null ? Math.round(intelScore * 100) : null,
      abuseipdb: abuseData?.abuseConfidence ?? null,
    },
    abuseConfidence: abuseData?.abuseConfidence ?? null,
    totalReports: abuseData?.totalReports ?? null,
    lastReported: abuseData?.lastReported ?? null,
    geo,
  };
}

// GET /score?ip=8.8.8.8
app.get("/score", async (req, res) => {
  try {
    const { ip } = req.query;
    if (!ip) return res.status(400).json({ error: "ip query param required" });

    const result = await analyzeIP(ip);
    res.json({
      ...result,
      timestamp: new Date().toISOString(),
      _paid: "$0.003 USDC / Base mainnet",
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

// GET /batch?ips=8.8.8.8,1.1.1.1,9.9.9.9
app.get("/batch", async (req, res) => {
  try {
    const raw = req.query.ips || "";
    const ips = raw.split(",").map(i => i.trim()).filter(Boolean).slice(0, 5);
    if (!ips.length) return res.status(400).json({ error: "ips param required (comma-separated, max 5)" });

    const results = await Promise.allSettled(ips.map(analyzeIP));
    const data = {};
    ips.forEach((ip, i) => {
      data[ip] = results[i].status === "fulfilled"
        ? results[i].value
        : { error: "lookup failed" };
    });

    res.json({
      count: ips.length,
      results: data,
      timestamp: new Date().toISOString(),
      _paid: "$0.01 USDC / Base mainnet",
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

// Autodiscovery
app.get("/.well-known/x402", (_req, res) => {
  res.json({
    version: "1",
    payTo: WALLET,
    network: "eip155:8453",
    currency: "USDC",
    name: "IP Fraud Intelligence API",
    description: "Multi-source IP fraud scoring combining GetIPIntel ML model + AbuseIPDB community reports. Returns 0-100 fraud score, VPN/proxy/TOR detection, and geolocation. No API key needed.",
    resources: [
      {
        path: "/score",
        method: "GET",
        description: "Combined fraud score for any IP from 2 independent sources.",
        params: "?ip=8.8.8.8",
        price: { amount: "0.003", currency: "USDC" },
      },
      {
        path: "/batch",
        method: "GET",
        description: "Batch fraud analysis for up to 5 IPs.",
        params: "?ips=8.8.8.8,1.1.1.1",
        price: { amount: "0.01", currency: "USDC" },
      },
    ],
  });
});

app.get("/", (_req, res) => {
  res.json({
    name: "IP Fraud Intelligence API",
    version: "2.0.0",
    description: "Multi-source IP fraud scoring via x402 micropayments. GetIPIntel ML + AbuseIPDB community reports. No API key needed.",
    payment: "USDC on Base mainnet (eip155:8453)",
    sources: ["GetIPIntel (ML fraud model)", "AbuseIPDB (community reports)", "ip-api.com (geolocation)"],
    endpoints: [
      { path: "GET /score", price: "$0.003", params: "?ip=8.8.8.8" },
      { path: "GET /batch", price: "$0.01", params: "?ips=8.8.8.8,1.1.1.1" },
    ],
    discovery: "GET /.well-known/x402",
  });
});

app.use((err, _req, res, _next) => {
  res.status(500).json({ error: err.message || "Internal server error" });
});

export default app;
