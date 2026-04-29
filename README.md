[![smithery badge](https://smithery.ai/badge/OjasKord/url-safety-validator-mcp)](https://smithery.ai/servers/OjasKord/url-safety-validator-mcp)

# URL Safety Validator MCP

**Stop your agent from fetching a dangerous URL before it's too late.**

Agents that process emails, scrape pages, or consume API responses encounter URLs from untrusted sources constantly. This server gives your agent a single call to gate every URL before it proceeds — returning a SAFE/SUSPICIOUS/DANGEROUS verdict backed by Google Web Risk, URLhaus, PhishTank, and AI analysis.

---

## What It Does

One tool: `check_url`. One call returns:

- **Verdict:** SAFE / SUSPICIOUS / DANGEROUS
- **AI trust score:** 0–100 (0 = definitely dangerous, 100 = definitely safe)
- **Threat categories:** phishing, malware, unwanted_software, typosquatting, newly_registered, suspicious_redirect, brand_impersonation
- **SSL status:** valid or not
- **Domain age:** registration date and age in days
- **Redirect chain flag:** detected from URL parameters
- **Database signals:** raw results from Google Web Risk, URLhaus, PhishTank
- **AI reasoning:** 2–3 sentence plain-English explanation
- **AI confidence:** HIGH / MEDIUM / LOW

AI-powered analysis — NOT a simple database lookup.

---

## When to Call This Tool

Call `check_url` BEFORE your agent:
- Fetches content from a URL found in an email
- Visits a link extracted from a scraped page or document
- Passes a URL to a browser tool or web scraper
- Stores or forwards a URL from any untrusted source
- Approves any outbound link in a content pipeline

If the verdict is DANGEROUS — halt. If SUSPICIOUS — flag for review. If SAFE — proceed.

---

## Data Sources

| Source | Type | Coverage |
|---|---|---|
| Google Web Risk | Commercial API | Malware, phishing, unwanted software |
| URLhaus (abuse.ch) | Free | Active malware distribution URLs |
| PhishTank | Free | Community-verified phishing URLs |
| RDAP | Free | Domain registration date |
| Anthropic Claude | AI | Trust scoring and reasoning synthesis |

---

## Pricing

| Tier | Calls | Price |
|---|---|---|
| Free | 10/month | No API key needed |
| Pro | Unlimited | $29/month — kordagencies.com |
| Enterprise | Unlimited + SLA | $99/month — kordagencies.com |

---

## Remote Usage (No Install)

```
https://url-safety-validator-mcp-production.up.railway.app
```

Add `x-api-key: YOUR_KEY` header for Pro/Enterprise tiers. Leave blank for free tier.

---

## Local Install (stdio)

```bash
npm install -g url-safety-validator-mcp
```

```json
{
  "mcpServers": {
    "url-safety-validator": {
      "command": "url-safety-validator-mcp",
      "env": {
        "ANTHROPIC_API_KEY": "your-key",
        "GOOGLE_WEB_RISK_API_KEY": "your-key"
      }
    }
  }
}
```

---

## Example Response

```json
{
  "url": "https://suspicious-domain.xyz/login",
  "hostname": "suspicious-domain.xyz",
  "verdict": "DANGEROUS",
  "trust_score": 4,
  "ssl_valid": true,
  "domain_age_days": 12,
  "redirect_chain_detected": false,
  "threat_categories": ["phishing", "newly_registered"],
  "reasoning": "Domain registered 12 days ago and confirmed in PhishTank as an active phishing site impersonating a financial institution. Google Web Risk flags this as SOCIAL_ENGINEERING.",
  "ai_confidence": "HIGH",
  "analysis_type": "AI-powered -- NOT a simple database lookup"
}
```

---

## Legal

Results are for informational purposes only. Verdict is a risk signal — not a guarantee of safety or danger. We do not log or store your query content. Full terms: kordagencies.com/terms.html

Provider: Kord Agencies Pte Ltd, Singapore.
