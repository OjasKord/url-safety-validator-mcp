# Changelog

All notable changes to URL Safety Validator MCP are documented here.

## [1.0.0] — 2026-04-22

### Initial Release
- `check_url` tool: SAFE/SUSPICIOUS/DANGEROUS verdict with AI trust score 0-100
- Google Web Risk integration (malware, phishing, unwanted software)
- URLhaus integration (active malware distribution URLs)
- PhishTank integration (community-verified phishing URLs)
- RDAP domain age lookup
- SSL validation check
- Redirect chain parameter detection
- AI-powered trust scoring and reasoning via Claude
- Free tier: 10 calls/month per IP, no API key required
- Pro tier: unlimited calls via API key
- Stripe webhook for automated key provisioning
- `/health`, `/deps`, `/stats` endpoints
- `/.well-known/mcp/server-card.json` for Smithery discovery
- Both stdio and HTTP POST MCP transport
