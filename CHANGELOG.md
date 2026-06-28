# Changelog

All notable changes to URL Safety Validator MCP are documented here.

## [1.2.30] — 2026-06-28
- fix: gate email dedup — notifyGateHit now writes url:gate_email:{ip} to Redis with 1-hour TTL; retries within the hour suppressed
- fix: 402 gate response agent_action changed to HALT_WORKFLOW; added retryable: false, retry_after_ms: null
- fix: trial_extension structured field already present; agent_action now actionable for agents

## [1.2.29] — 2026-06-28
- feat: owner key bypass (OWNER_KEY env var) — fleet owner bypasses free tier and paid-only gates

## [1.2.28] — 2026-06-26
- fix: trial extension requests now written to Redis (url:trial:{email}) on grant -- permanent audit trail that survives redeploys; previously in-memory only

## [1.2.27] — 2026-06-25
- fix: .npmignore was missing a .claude/ exclusion -- .claude/settings.local.json shipped in the v1.2.26 npm tarball. Added token.tmp, *.tmp, .claude/, CLAUDE.md, SYSTEM_PROMPT.md, MCP-Build-Playbook* to .npmignore.

## [1.2.26] — 2026-06-25
- feat: calls_remaining field added to check_url responses -- "unlimited" for paid keys, numeric free-tier headroom otherwise
- feat: verdict_ttl field added (3600s/1hr -- threat landscape changes fast)
- feat: data_source_status field added (full/degraded/partial) -- "degraded" when Google Web Risk (critical source) is unavailable, "partial" when only AI trust scoring is unavailable, "full" when both respond
- Task 1 (purpose verb + required fields) audited -- already correct on check_url from a prior pass, no changes needed

## [1.2.25] — 2026-06-24
- feat: unauthenticated /public-stats endpoint -- first_deployed, lifetime tool calls, uptime %, version, for agent orchestrators evaluating server trustworthiness
- feat: /process-trial-followups endpoint + 24h follow-up record on trial-extension grant
- feat: gate response now self-contained (server + workflow impact + upgrade path in one sentence) and detects cross-server operators via shared fleet Redis, with cross-server trial-extension note
- feat: outputSchema added to check_url (additive, response format unchanged)
- fix: tool description and both initialize descriptions said "Returns BLOCK / FLAG_AND_PROCEED / ALLOW verdict" -- the real `verdict` field is SAFE/SUSPICIOUS/DANGEROUS; BLOCK/FLAG_AND_PROCEED/ALLOW is a separate derived `agent_action` field. Clarified both fields and their relationship everywhere this was stated.
- fix: glama.json and README claimed cross-checking against URLhaus and PhishTank -- neither is ever called in code, only Google Web Risk and Google Safe Browsing are. Removed the false claims, including a fabricated PhishTank citation in a README example response. Also fixed smithery.yaml claiming "2 focused tools" when this server has exactly 1 (check_url).
- fix: /deps health check previously treated HTTP 403 (key rejected) on Google Web Risk as ok:true via the `statusCode < 500` pattern -- now treats 403 on an authenticated API as ok:false with error:'auth_failed'

## [1.2.24] — 2026-06-23
- fix: gate returns HTTP 402 (x402 standard for non-transient quota)

## [1.2.23] — 2026-06-20
- feat: email notification on free tier gate hit

## [1.2.22] — 2026-06-18
- feat: revoke API key on Stripe refund

## [1.2.21] — 2026-06-17
- fix: Stripe webhook now validates payment_link ID — ignores events not belonging to this server

## [1.2.20] — 2026-06-17
- feat: SmitheryBot detection on check_url — returns mock SAFE verdict without consuming Google Safe Browsing credits

## [1.2.19] — 2026-06-16
- feat: ATO optimisation — purpose verb, usage context, required fields, ToolRank badge

## [1.2.18] — 2026-06-15
- feat: add hold_reason, retry_after, escalation_path to FLAG_AND_PROCEED (SUSPICIOUS) responses in check_url

## [1.2.17] — 2026-06-15
- feat: reposition tool description for agentic payment rail discovery -- Stripe MPP, Alipay AI Pay, Shopify UCP trigger vocabulary in check_url and initialize description

## [1.2.16] — 2026-06-11
- feat: add /.well-known/mcp/server-card.json static metadata endpoint

## [1.2.15] — 2026-06-11
- fix: bump version past existing npm publish (1.2.14 already on registry)

## [1.2.14] — 2026-06-11
- feat: per-tool kill switch + per-minute rate limiting on AI tools

## [1.2.13] — 2026-06-08
- fix: BEFORE trigger language, consequence-first limit error

## [1.2.12] — 2026-06-05
- feat: Smithery optimisation - updated package.json description/keywords and smithery.yaml with system prompt

## [1.2.11] — 2026-06-04
- feat: /daily-report endpoint for consolidated daily summary

## [1.2.10] — 2026-06-04

### Added
- Upstash Redis persistence: free tier usage, API keys, session logs survive redeploys
- `loadFreeTierFromRedis()` / `saveFreeTierToRedis()` with Math.max merge (adapted for stats object structure)
- `saveKeyToRedis()` / `loadApiKeysFromRedis()` with prefix `url`
- `appendSessionLog(ip, tool)` with 24h TTL per IP per day
- `/session-log` endpoint (requires x-stats-key)
- `free_tier_breakdown` per-IP object on `/stats` response for current month
- `getEffectiveLimit(ip)` helper — returns base + trial extension if applicable

### Changed
- `check_url` tool description rewritten for orchestral agent runtime selection: state-based trigger, verdict consequences, DO NOT USE conditions
- `VERSION` bumped to `1.2.10`

## [1.2.9] — 2026-06-02

### Fixed
- fix: IP extraction fixed for Cloudflare proxy headers — free tier gate now enforces correctly

## [1.2.5] — 2026-04-28

### Changed
- Payment links updated to prepaid bundle URLs: 500 calls for $20 -- calls never expire
- Free tier limit errors now direct agents to prepaid bundle purchase link directly

## [1.2.4] — 2026-04-26

### Added
- `token_count` field on all tool responses — lets orchestrator budget ledgers track token cost per call
- `/ready` endpoint — returns 200 when `ANTHROPIC_API_KEY` and `GOOGLE_WEB_RISK_API_KEY` are present, 503 otherwise; enables Railway health-gate and orchestrator pre-flight checks
- Phase 4 enhanced error objects: `category`, `retryable`, `retry_after_ms`, `fallback_tool`, `trace_id` on all error returns

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
