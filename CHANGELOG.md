# Changelog

All notable changes to URL Safety Validator MCP are documented here.

## [1.2.3] — 2026-04-26

### Improved
- Tool description rewritten with TCO framework: irresistibility opening, carry-cost argument, catastrophic failure scenario, exact data source hostnames, prepaid bundle pricing last
- Initialize `serverInfo.description` rewritten with TCO framework for Smithery and Claude Desktop discovery
- `agent_action` and `likely_cause` added to catch-all HTTP error handler (was returning bare `{error: message}`)

## [1.2.2] — 2026-04-25

### Fixed
- CRITICAL: Stripe webhook now sends API key via Resend email on `checkout.session.completed` -- paying customers were not receiving their keys
- `agent_action` field added to `check_url` result (BLOCK / FLAG_AND_PROCEED / ALLOW) -- field was promised in tool description but missing from response
- `agent_action` and `likely_cause` added to all error responses
- `/stats` endpoint now returns `tool_usage` and `recent_calls` fields -- dashboard was showing `--` for both

### Improved
- `check_url` tool description updated: source hostnames, latency signal, corrected agent_action guidance
- `serverInfo` description added to both HTTP and stdio initialize responses -- improves Smithery and Claude Desktop discoverability
- `source_url` corrected from kordagencies.com to webrisk.googleapis.com

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
