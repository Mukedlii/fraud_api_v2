# IP Fraud Intelligence API

> Multi-source IP fraud scoring for AI agents — no API key, pay per request in USDC on Base.

![icon](./icon.svg)

## What it does

Analyzes any IP address using **two independent fraud intelligence sources** and returns a unified 0–100 fraud score with VPN/proxy/TOR detection and geolocation.

| Source | Type | Weight |
|---|---|---|
| GetIPIntel | ML-based VPN/proxy/TOR model | 60% |
| AbuseIPDB | Community abuse reports (90-day window) | 40% |

## Endpoints

| Endpoint | Price | Description |
|---|---|---|
| `GET /score` | $0.003 | Full fraud analysis for a single IP |
| `GET /batch` | $0.010 | Fraud analysis for up to 5 IPs |
| `GET /` | FREE | API docs |
| `GET /.well-known/x402` | FREE | Autodiscovery |

## Example

```bash
# Single IP
curl "https://fraud-api-v2.vercel.app/score?ip=8.8.8.8"

# Batch
curl "https://fraud-api-v2.vercel.app/batch?ips=8.8.8.8,1.1.1.1,185.220.101.1"
```

### Response

```json
{
  "ip": "185.220.101.1",
  "fraudScore": 100,
  "riskLevel": "critical",
  "isVpnOrProxy": true,
  "isTor": true,
  "sources": {
    "getipintel": 100,
    "abuseipdb": 100
  },
  "abuseConfidence": 100,
  "totalReports": 140,
  "lastReported": "2026-04-28T00:33:55+00:00",
  "geo": {
    "country": "Germany",
    "city": "Brandenburg",
    "isp": "Stiftung Erneuerbare Freiheit"
  }
}
```

### Risk levels

| Score | Level | Meaning |
|---|---|---|
| 0–14 | `safe` | Legitimate user |
| 15–39 | `low` | Monitor |
| 40–69 | `medium` | Additional verification recommended |
| 70–89 | `high` | Likely VPN/proxy |
| 90–100 | `critical` | Confirmed VPN/proxy/TOR/banned IP |

## Payment

USDC on Base mainnet (`eip155:8453`) via [x402 protocol](https://x402.org). No account or API key needed — agents pay directly per request.

## Deploy

### 1. Clone

```bash
git clone https://github.com/YOUR_USERNAME/fraud-api-v2
cd fraud-api-v2
```

### 2. Set environment variables in Vercel

```
WALLET_ADDRESS=0x...
CDP_API_KEY_ID=...
CDP_API_KEY_SECRET=...
CONTACT_EMAIL=your@email.com
ABUSEIPDB_API_KEY=...
```

### 3. Deploy

```bash
npm i -g vercel
vercel --prod
```

## Built with

- [x402 protocol](https://x402.org) — pay-per-request micropayments
- [Coinbase CDP](https://portal.cdp.coinbase.com) — payment facilitation on Base
- [GetIPIntel](https://getipintel.net) — ML fraud scoring
- [AbuseIPDB](https://abuseipdb.com) — community abuse reports
- [ip-api.com](https://ip-api.com) — geolocation
