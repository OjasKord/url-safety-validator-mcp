'use strict';
const http = require('http');
const https = require('https');
const fs = require('fs');
const crypto = require('crypto');
const { Readable } = require('stream');

const VERSION = '1.2.17';
const PRO_UPGRADE_URL = 'https://buy.stripe.com/5kQeVc9Ah4n3c8c0h2ebu0t';
const ENTERPRISE_UPGRADE_URL = 'https://buy.stripe.com/4gMdR88wddXDfko0h2ebu0u';
const PORT = process.env.PORT || 3000;
const STATS_KEY = process.env.STATS_KEY || 'ojas2026';
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';
const GOOGLE_WEB_RISK_API_KEY = process.env.GOOGLE_WEB_RISK_API_KEY || '';
const GOOGLE_SAFE_BROWSING_API_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const PERSIST_FILE = '/tmp/urlsafety_stats.json';

const LEGAL_DISCLAIMER = 'Results sourced from Google Web Risk, Google Safe Browsing, and AI analysis. We do not log or store your query content. Results are for informational purposes only and do not constitute security advice. Verdict is a risk signal -- not a guarantee of safety or danger. Provider maximum liability is limited to subscription fees paid in the preceding 3 months. Full terms: kordagencies.com/terms.html';

const FREE_LIMIT = 10;

// ─── Stats ────────────────────────────────────────────────────────────────────
let stats = { free_tier_calls_by_ip: {}, total_checks: 0, safe_count: 0, suspicious_count: 0, dangerous_count: 0, started_at: new Date().toISOString() };
const apiKeys = new Map();
const usageLog = [];
const toolUsageCounts = {};
const trialExtensions = new Map();
const TRIAL_EXTENSION_CALLS = 10;

const perMinuteUsage = new Map();

function checkPerMinuteLimit(ip, toolName, limit) {
  const minuteKey = ip + ':' + toolName + ':' + new Date().toISOString().slice(0, 16);
  const count = perMinuteUsage.get(minuteKey) || 0;
  if (count >= limit) return false;
  perMinuteUsage.set(minuteKey, count + 1);
  if (perMinuteUsage.size > 10000) {
    const currentMinute = new Date().toISOString().slice(0, 16);
    for (const [key] of perMinuteUsage) {
      if (!key.includes(currentMinute)) perMinuteUsage.delete(key);
    }
  }
  return true;
}

const REDIS_PREFIX = 'url';
const FREE_TIER_REDIS_KEY = 'url:free_tier_usage';
const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

function loadStats() {
  try {
    const data = JSON.parse(fs.readFileSync(PERSIST_FILE, 'utf8'));
    stats = data.stats || stats;
    if (data.api_keys) data.api_keys.forEach(([k, v]) => apiKeys.set(k, v));
    if (data.toolUsageCounts) Object.assign(toolUsageCounts, data.toolUsageCounts);
    if (data.trialExtensions) data.trialExtensions.forEach(([k, v]) => trialExtensions.set(k, v));
  } catch(e) { /* fresh start */ }
}

function saveStats() {
  try {
    fs.writeFileSync(PERSIST_FILE, JSON.stringify({ stats, api_keys: [...apiKeys.entries()], toolUsageCounts, trialExtensions: [...trialExtensions.entries()] }));
  } catch(e) {}
}

loadStats();

function nowISO() { return new Date().toISOString(); }

// ─── Email ────────────────────────────────────────────────────────────────────
async function sendEmail(to, subject, html) {
  return new Promise((resolve) => {
    const body = JSON.stringify({ from: 'URL Safety Validator <ojas@kordagencies.com>', to: [to], subject, html });
    const req = https.request({
      hostname: 'api.resend.com', path: '/emails', method: 'POST',
      headers: { 'Authorization': 'Bearer ' + RESEND_API_KEY, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, res => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode, body: d })); });
    req.on('error', e => resolve({ error: e.message }));
    req.write(body); req.end();
  });
}

async function sendApiKeyEmail(email, apiKey, plan) {
  const planLabel = plan === 'enterprise' ? 'Enterprise' : 'Pro';
  const limit = plan === 'enterprise' ? 'Unlimited' : '500';
  const html = '<!DOCTYPE html><html><body style="font-family:monospace;background:#080A0F;color:#E8EDF5;padding:40px;max-width:600px;margin:0 auto"><div style="border:1px solid rgba(0,229,195,0.3);border-radius:8px;padding:32px"><div style="color:#00E5C3;font-size:13px;letter-spacing:0.2em;text-transform:uppercase;margin-bottom:24px">URL Safety Validator MCP -- ' + planLabel + ' Plan</div><h1 style="font-size:24px;font-weight:700;margin-bottom:8px;color:#FFFFFF">Your API key is ready.</h1><div style="background:#141B24;border:1px solid rgba(255,255,255,0.1);border-radius:6px;padding:20px;margin-bottom:24px"><div style="color:#5A6478;font-size:11px;text-transform:uppercase;margin-bottom:8px">Your API Key</div><div style="color:#00E5C3;font-size:14px;word-break:break-all">' + apiKey + '</div></div><div style="background:#141B24;border:1px solid rgba(255,255,255,0.1);border-radius:6px;padding:20px;margin-bottom:24px"><div style="color:#5A6478;font-size:11px;text-transform:uppercase;margin-bottom:8px">MCP Config</div><div style="color:#86EFAC;font-size:12px">{"url-safety-validator":{"url":"https://url-safety-validator-mcp-production.up.railway.app","headers":{"x-api-key":"' + apiKey + '"}}}</div></div><div style="background:#141B24;border:1px solid rgba(255,255,255,0.1);border-radius:6px;padding:20px;margin-bottom:24px"><div style="color:#E8EDF5;font-size:13px">Plan: ' + planLabel + ' | URL checks: ' + limit + '/month</div></div><div style="background:#0D1219;border-radius:6px;padding:16px;margin-bottom:24px;font-size:11px;color:#5A6478;line-height:1.7">Results are informational only. Verdict is a risk signal not a safety guarantee. Liability capped at 3 months fees. Full terms: kordagencies.com/terms.html</div><p style="color:#5A6478;font-size:12px">Questions? ojas@kordagencies.com</p></div></body></html>';
  return sendEmail(email, 'Your URL Safety Validator MCP ' + planLabel + ' API Key', html);
}

// ─── Free/Paid Tier ───────────────────────────────────────────────────────────
function getMonthKey() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`;
}

function getEffectiveLimit(ip) {
  for (const record of trialExtensions.values()) {
    if (record.ip === ip) return FREE_LIMIT + TRIAL_EXTENSION_CALLS;
  }
  return FREE_LIMIT;
}

function checkTier(ip, apiKey) {
  if (apiKey && apiKeys.has(apiKey)) return { allowed: true, paid: true, remaining: Infinity };
  const month = getMonthKey();
  const ipMap = stats.free_tier_calls_by_ip;
  if (!ipMap[ip]) ipMap[ip] = {};
  const used = ipMap[ip][month] || 0;
  if (used >= FREE_LIMIT) return { allowed: false, paid: false, remaining: 0 };
  return { allowed: true, paid: false, remaining: FREE_LIMIT - used };
}

function recordCall(ip, apiKey) {
  if (apiKey && apiKeys.has(apiKey)) return;
  const month = getMonthKey();
  if (!stats.free_tier_calls_by_ip[ip]) stats.free_tier_calls_by_ip[ip] = {};
  stats.free_tier_calls_by_ip[ip][month] = (stats.free_tier_calls_by_ip[ip][month] || 0) + 1;
}

// ─── REDIS HELPERS ────────────────────────────────────────────────────────────

async function redisGet(key) {
  try {
    const res = await fetch(
      `${UPSTASH_URL}/get/${encodeURIComponent(key)}`,
      { headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` } }
    );
    const data = await res.json();
    if (data.error) console.error('[Redis] redisGet error:', data.error, 'key:', key);
    if (!data.result) return null;
    return JSON.parse(data.result);
  } catch(e) { return null; }
}

async function redisSet(key, value) {
  try {
    const res = await fetch(`${process.env.UPSTASH_REDIS_REST_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(JSON.stringify(value))}`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${process.env.UPSTASH_REDIS_REST_TOKEN}` }
    });
    const data = await res.json();
    if (data.error) console.error('[Redis] redisSet error:', data.error, 'key:', key);
  } catch(e) { console.error('[Redis] redisSet failed:', e); }
}

async function redisExpire(key, seconds) {
  try {
    const res = await fetch(
      `${UPSTASH_URL}/expire/${encodeURIComponent(key)}/${seconds}`,
      { method: 'POST', headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` } }
    );
    const data = await res.json();
    if (data.error) console.error('[Redis] redisExpire error:', data.error, 'key:', key);
  } catch(e) { console.error('[Redis] redisExpire failed:', e); }
}

async function redisKeys(pattern) {
  try {
    const res = await fetch(
      `${UPSTASH_URL}/keys/${encodeURIComponent(pattern)}`,
      { headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` } }
    );
    const data = await res.json();
    if (data.error) console.error('[Redis] redisKeys error:', data.error, 'pattern:', pattern);
    return data.result || [];
  } catch(e) { return []; }
}

async function appendSessionLog(ip, tool) {
  try {
    const ipSafe = ip.replace(/:/g, '_').replace(/\s/g, '');
    const dayKey = new Date().toISOString().slice(0, 10);
    const key = `${REDIS_PREFIX}:session:${ipSafe}:${dayKey}`;
    const existing = await redisGet(key) || [];
    existing.push({ tool, timestamp: new Date().toISOString() });
    await redisSet(key, existing);
    await redisExpire(key, 86400);
  } catch(e) { console.error('[SessionLog] internal error:', e); }
}

async function saveKeyToRedis(apiKey, record) {
  await redisSet(`${REDIS_PREFIX}:key:${apiKey}`, record);
}

async function loadApiKeysFromRedis() {
  const keys = await redisKeys(`${REDIS_PREFIX}:key:*`);
  for (const redisKey of keys) {
    const record = await redisGet(redisKey);
    if (record) {
      const apiKey = redisKey.replace(`${REDIS_PREFIX}:key:`, '');
      apiKeys.set(apiKey, record);
    }
  }
  console.log(`Loaded ${apiKeys.size} API keys from Redis`);
}

async function loadFreeTierFromRedis() {
  try {
    const data = await redisGet(FREE_TIER_REDIS_KEY);
    if (data && typeof data === 'object') {
      Object.assign(stats.free_tier_calls_by_ip, data);
      console.log('[FreeTier] Loaded ' + Object.keys(stats.free_tier_calls_by_ip).length + ' IPs from Redis');
    }
  } catch(e) { console.error('[FreeTier] load failed:', e); }
}

async function saveFreeTierToRedis() {
  try {
    const existing = await redisGet(FREE_TIER_REDIS_KEY) || {};
    for (const [ip, months] of Object.entries(stats.free_tier_calls_by_ip)) {
      if (!existing[ip]) existing[ip] = {};
      for (const [month, count] of Object.entries(months)) {
        existing[ip][month] = Math.max(existing[ip][month] || 0, count);
      }
    }
    await redisSet(FREE_TIER_REDIS_KEY, existing);
  } catch(e) { console.error('[FreeTier] save failed:', e); }
}

// ─── HTTP helper ──────────────────────────────────────────────────────────────
function httpsGet(hostname, path, headers, timeout) {
  return new Promise((resolve) => {
    const req = https.request({ hostname, path, method: 'GET', headers: Object.assign({ 'User-Agent': 'MCPUrlSafetyValidator/1.0' }, headers || {}) }, (res) => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => resolve({ ok: res.statusCode < 400, status: res.statusCode, body }));
    });
    req.on('error', (e) => resolve({ ok: false, status: 0, error: e.message }));
    req.setTimeout(timeout || 6000, () => { req.destroy(); resolve({ ok: false, status: 0, error: 'timeout' }); });
    req.end();
  });
}

function httpsPost(hostname, path, postBody, headers, timeout) {
  return new Promise((resolve) => {
    const data = typeof postBody === 'string' ? postBody : JSON.stringify(postBody);
    const opts = {
      hostname, path, method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data), 'User-Agent': 'MCPUrlSafetyValidator/1.0' }, headers || {})
    };
    const req = https.request(opts, (res) => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => resolve({ ok: res.statusCode < 400, status: res.statusCode, body }));
    });
    req.on('error', (e) => resolve({ ok: false, status: 0, error: e.message }));
    req.setTimeout(timeout || 8000, () => { req.destroy(); resolve({ ok: false, status: 0, error: 'timeout' }); });
    req.write(data);
    req.end();
  });
}

// ─── URL parsing helper ───────────────────────────────────────────────────────
function parseUrl(rawUrl) {
  try {
    let u = rawUrl.trim();
    if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
    const parsed = new URL(u);
    return { valid: true, href: parsed.href, hostname: parsed.hostname, protocol: parsed.protocol };
  } catch(e) {
    return { valid: false };
  }
}

// ─── Google Web Risk ──────────────────────────────────────────────────────────
async function checkGoogleWebRisk(url) {
  if (!GOOGLE_WEB_RISK_API_KEY) return { available: false, reason: 'GOOGLE_WEB_RISK_API_KEY not set' };
  const encoded = encodeURIComponent(url);
  const path = `/v1/uris:search?threatTypes=MALWARE&threatTypes=SOCIAL_ENGINEERING&threatTypes=UNWANTED_SOFTWARE&uri=${encoded}&key=${GOOGLE_WEB_RISK_API_KEY}`;
  const r = await httpsGet('webrisk.googleapis.com', path, {}, 6000);
  if (!r.ok) return { available: false, reason: `Google Web Risk API error: ${r.status}` };
  try {
    const parsed = JSON.parse(r.body);
    const threat = parsed.threat;
    if (threat && threat.threatTypes && threat.threatTypes.length > 0) {
      return { available: true, flagged: true, threat_types: threat.threatTypes, expires_time: threat.expireTime };
    }
    return { available: true, flagged: false, threat_types: [] };
  } catch(e) {
    return { available: false, reason: 'Parse error' };
  }
}

// ─── Google Safe Browsing ────────────────────────────────────────────────────
async function checkGoogleSafeBrowsing(url) {
  if (!GOOGLE_SAFE_BROWSING_API_KEY) return { available: false, reason: 'GOOGLE_SAFE_BROWSING_API_KEY not set' };
  const body = JSON.stringify({
    client: { clientId: 'kord-url-safety-mcp', clientVersion: VERSION },
    threatInfo: {
      threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url }]
    }
  });
  const path = `/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_API_KEY}`;
  const r = await httpsPost('safebrowsing.googleapis.com', path, body, { 'Content-Type': 'application/json' }, 6000);
  if (!r.ok) return { available: false, reason: `Google Safe Browsing error: ${r.status}` };
  try {
    const parsed = JSON.parse(r.body);
    const matches = parsed.matches || [];
    return {
      available: true,
      flagged: matches.length > 0,
      threat_types: matches.map(m => m.threatType),
      platform_types: matches.map(m => m.platformType)
    };
  } catch(e) {
    return { available: false, reason: 'Parse error' };
  }
}

// ─── WHOIS domain age via RDAP ────────────────────────────────────────────────
async function checkDomainAge(hostname) {
  const r = await httpsGet('rdap.org', `/domain/${hostname}`, {}, 6000);
  if (!r.ok) return { available: false, reason: 'RDAP unavailable' };
  try {
    const parsed = JSON.parse(r.body);
    const events = parsed.events || [];
    const reg = events.find(e => e.eventAction === 'registration');
    if (!reg) return { available: true, registration_date: null, domain_age_days: null };
    const regDate = new Date(reg.eventDate);
    const ageDays = Math.floor((Date.now() - regDate.getTime()) / 86400000);
    return { available: true, registration_date: reg.eventDate, domain_age_days: ageDays };
  } catch(e) {
    return { available: false, reason: 'Parse error' };
  }
}

// ─── SSL check ────────────────────────────────────────────────────────────────
async function checkSSL(hostname) {
  return new Promise((resolve) => {
    const req = https.request({ hostname, path: '/', method: 'HEAD', rejectUnauthorized: true }, (res) => {
      res.resume();
      resolve({ valid_ssl: true, status: res.statusCode });
    });
    req.on('error', (e) => resolve({ valid_ssl: false, error: e.message }));
    req.setTimeout(5000, () => { req.destroy(); resolve({ valid_ssl: false, error: 'timeout' }); });
    req.end();
  });
}

// ─── AI Trust Score ───────────────────────────────────────────────────────────
async function getAITrustScore(url, hostname, signals) {
  if (!ANTHROPIC_API_KEY) return { available: false, reason: 'ANTHROPIC_API_KEY not set' };
  const prompt = `You are a URL safety analyst. Assess this URL and return a JSON object only, no markdown.

URL: ${url}
Hostname: ${hostname}

Signals from external databases:
${JSON.stringify(signals, null, 2)}

Return this exact JSON structure:
{
  "trust_score": <integer 0-100, where 0=definitely dangerous, 100=definitely safe>,
  "verdict": "<SAFE|SUSPICIOUS|DANGEROUS>",
  "threat_categories": [<list of applicable strings: "phishing", "malware", "unwanted_software", "typosquatting", "newly_registered", "suspicious_redirect", "brand_impersonation", "none">],
  "reasoning": "<2-3 sentence plain English explanation of why this verdict was reached>",
  "confidence": "<HIGH|MEDIUM|LOW>"
}

Rules:
- trust_score 0-29 = DANGEROUS, 30-64 = SUSPICIOUS, 65-100 = SAFE
- If Google Web Risk flagged it OR Google Safe Browsing confirmed it, verdict MUST be DANGEROUS
- Domain age under 30 days = add "newly_registered" to threat_categories and lower trust_score by at least 20
- No SSL on a login-looking URL = lower score significantly
- Consider the full picture -- a newly registered domain with no database hits is still SUSPICIOUS not SAFE`;

  const body = JSON.stringify({
    model: 'claude-sonnet-4-6',
    max_tokens: 500,
    messages: [{ role: 'user', content: prompt }]
  });

  const r = await httpsPost('api.anthropic.com', '/v1/messages', body, {
    'x-api-key': ANTHROPIC_API_KEY,
    'anthropic-version': '2023-06-01'
  }, 12000);

  if (!r.ok) return { available: false, reason: `Anthropic API error: ${r.status}` };
  try {
    const parsed = JSON.parse(r.body);
    const text = parsed.content[0].text.replace(/```json|```/g, '').trim();
    const result = JSON.parse(text);
    return { available: true, ...result };
  } catch(e) {
    return { available: false, reason: 'AI parse error: ' + e.message };
  }
}

// ─── Core check_url logic ─────────────────────────────────────────────────────
async function checkUrl(rawUrl) {
  const parsed = parseUrl(rawUrl);
  if (!parsed.valid) {
    return {
      error: 'Invalid URL format. Provide a full URL like https://example.com',
      url: rawUrl,
      likely_cause: 'required field missing or malformed URL provided',
      retryable: false,
      retry_after_ms: null,
      fallback_tool: null,
      agent_action: 'Fix the URL format before retrying. Ensure it starts with https:// or http://',
      category: 'invalid_input',
      trace_id: crypto.randomBytes(8).toString('hex'),
      _disclaimer: LEGAL_DISCLAIMER
    };
  }

  const { href, hostname, protocol } = parsed;

  const [webRisk, safeBrowsing, domainAge, ssl] = await Promise.all([
    checkGoogleWebRisk(href),
    checkGoogleSafeBrowsing(href),
    checkDomainAge(hostname),
    protocol === 'https:' ? checkSSL(hostname) : Promise.resolve({ valid_ssl: false, error: 'HTTP only -- no SSL' })
  ]);

  const signals = { google_web_risk: webRisk, google_safe_browsing: safeBrowsing, domain_age: domainAge, ssl };

  const ai = await getAITrustScore(href, hostname, signals);

  // Determine final verdict -- hard overrides
  let verdict = ai.available ? ai.verdict : 'SUSPICIOUS';
  let trust_score = ai.available ? ai.trust_score : 40;

  if (webRisk.available && webRisk.flagged) { verdict = 'DANGEROUS'; trust_score = Math.min(trust_score, 5); }
  if (safeBrowsing.available && safeBrowsing.flagged) { verdict = 'DANGEROUS'; trust_score = Math.min(trust_score, 5); }

  // Redirect chain flag
  let redirect_chain_detected = false;
  try {
    const pathAndQuery = href.replace(`${protocol}//${hostname}`, '');
    if (pathAndQuery.includes('url=') || pathAndQuery.includes('redirect=') || pathAndQuery.includes('goto=') || pathAndQuery.includes('link=')) {
      redirect_chain_detected = true;
    }
  } catch(e) {}

  if (verdict === 'SAFE') stats.safe_count++;
  else if (verdict === 'SUSPICIOUS') stats.suspicious_count++;
  else stats.dangerous_count++;
  stats.total_checks++;

  const result = {
    url: href,
    hostname,
    verdict,
    agent_action: verdict === 'DANGEROUS' ? 'BLOCK' : verdict === 'SUSPICIOUS' ? 'FLAG_AND_PROCEED' : 'ALLOW',
    trust_score,
    ssl_valid: ssl.valid_ssl,
    domain_age_days: domainAge.available ? domainAge.domain_age_days : null,
    domain_registered: domainAge.available ? domainAge.registration_date : null,
    redirect_chain_detected,
    threat_categories: ai.available ? ai.threat_categories : [],
    reasoning: ai.available ? ai.reasoning : 'AI analysis unavailable -- verdict based on database signals only.',
    ai_confidence: ai.available ? ai.confidence : null,
    analysis_type: 'AI-powered -- NOT a simple database lookup',
    database_signals: {
      google_web_risk: webRisk.available ? { flagged: webRisk.flagged, threat_types: webRisk.threat_types } : { available: false, reason: webRisk.reason },
      google_safe_browsing: safeBrowsing.available ? { flagged: safeBrowsing.flagged, threat_types: safeBrowsing.threat_types } : { available: false, reason: safeBrowsing.reason }
    },
    checked_at: nowISO(),
    source_url: 'webrisk.googleapis.com',
    _disclaimer: LEGAL_DISCLAIMER
  };

  result.token_count = Math.ceil(JSON.stringify(result).length / 4);
  saveStats();
  return result;
}

// ─── Tool definition ──────────────────────────────────────────────────────────
const TOOL_DEFINITION = {
  name: 'check_url',
  idempotent: true,
  description: 'Call this BEFORE your agent fetches, follows, or forwards any URL in an agentic commerce workflow -- at the moment a merchant site, supplier portal, or payment redirect URL is received and no navigation has occurred. Checks live against Google Web Risk (webrisk.googleapis.com) and Google Safe Browsing (safebrowsing.googleapis.com). Returns BLOCK / FLAG_AND_PROCEED / ALLOW verdict with trust score 0-100 and threat categories. A payment executed on a phishing domain via Stripe MPP, Alipay AI Pay, or Shopify UCP has no recovery path -- the redirect is the attack vector. A DANGEROUS verdict means halt immediately. Returns machine-ready verdict, no further analysis needed.',
  inputSchema: {
    type: 'object',
    properties: {
      url: { type: 'string', description: 'The URL to check. Full URL preferred (e.g. https://example.com/path). Bare domains also accepted.' }
    },
    required: ['url']
  }
};

// ─── Stripe verification ──────────────────────────────────────────────────────
function verifyStripeSignature(body, sig, secret) {
  if (!secret || !sig) return false;
  try {
    const parts = sig.split(',').reduce((acc, part) => { const [k, v] = part.split('='); acc[k] = v; return acc; }, {});
    const timestamp = parts['t'], expected = parts['v1'];
    if (!timestamp || !expected) return false;
    const computed = crypto.createHmac('sha256', secret).update(timestamp + '.' + body, 'utf8').digest('hex');
    return crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(expected));
  } catch(e) { return false; }
}

// ─── CORS ─────────────────────────────────────────────────────────────────────
const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, x-api-key, x-stats-key'
};

// ─── MCP stdio transport ──────────────────────────────────────────────────────
function setupStdio() {
  if (!process.stdin.isTTY) {
    let buffer = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', async (chunk) => {
      buffer += chunk;
      let nl;
      while ((nl = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, nl).trim();
        buffer = buffer.slice(nl + 1);
        if (!line) continue;
        try {
          const request = JSON.parse(line);
          let response;
          if (request.method === 'initialize') {
            response = { jsonrpc: '2.0', id: request.id, result: { protocolVersion: '2024-11-05', capabilities: { tools: {}, resources: {}, prompts: {} }, serverInfo: { name: 'url-safety-validator-mcp', version: VERSION, description: 'Every agentic commerce workflow built on Stripe MPP, Alipay AI Pay, or Shopify UCP has a moment where the agent must navigate to a merchant or supplier URL before it can proceed. This server answers that question in one call -- returning a machine-readable BLOCK / FLAG_AND_PROCEED / ALLOW verdict checked live against Google Web Risk and Google Safe Browsing, every call. Used before any agent URL fetch, page navigation, or redirect follow in payment and procurement workflows.' } } };
          } else if (request.method === 'notifications/initialized') {
            continue;
          } else if (request.method === 'tools/list') {
            response = { jsonrpc: '2.0', id: request.id, result: { tools: [TOOL_DEFINITION] } };
          } else if (request.method === 'resources/list') {
            response = { jsonrpc: '2.0', id: request.id, result: { resources: [] } };
          } else if (request.method === 'prompts/list') {
            response = { jsonrpc: '2.0', id: request.id, result: { prompts: [] } };
          } else if (request.method === 'tools/call' && request.params?.name === 'check_url') {
            const _ks = 'TOOL_DISABLED_CHECK_URL';
            if (process.env[_ks] === 'true') {
              response = { jsonrpc: '2.0', id: request.id, result: { content: [{ type: 'text', text: JSON.stringify({ error: 'This tool is temporarily unavailable for maintenance.', agent_action: 'RETRY_IN_30_MIN', retryable: true, retry_after_ms: 1800000 }) }] } };
            } else {
              const url = request.params?.arguments?.url;
              if (!url) { response = { jsonrpc: '2.0', id: request.id, error: { code: -32602, message: 'url parameter required' } }; }
              else {
                const result = await checkUrl(url);
                response = { jsonrpc: '2.0', id: request.id, result: { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] } };
              }
            }
          } else {
            response = { jsonrpc: '2.0', id: request.id, error: { code: -32601, message: 'Method not found: ' + request.method } };
          }
          process.stdout.write(JSON.stringify(response) + '\n');
        } catch(e) {
          process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }) + '\n');
        }
      }
    });
  }
}

// ─── HTTP server ──────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') { res.writeHead(200, cors); res.end(); return; }

  if (req.url === '/health' && (req.method === 'GET' || req.method === 'HEAD')) {
    res.writeHead(200, { ...cors, 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', version: VERSION, service: 'url-safety-validator-mcp', paid_keys_issued: apiKeys.size, total_checks: stats.total_checks }));
    return;
  }

  if (req.url === '/ready' && (req.method === 'GET' || req.method === 'HEAD')) {
    const checks = { anthropic: !!ANTHROPIC_API_KEY, google_web_risk: !!GOOGLE_WEB_RISK_API_KEY };
    const ready = checks.anthropic && checks.google_web_risk;
    res.writeHead(ready ? 200 : 503, { ...cors, 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: ready ? 'ready' : 'not_ready', version: VERSION, checks }));
    return;
  }

  if (req.url === '/deps' && req.method === 'GET') {
    const depCheck = (hostname, path, extraHeaders) => new Promise((resolve) => {
      const r = https.request({ hostname, path, method: 'GET', headers: { 'User-Agent': 'MCP-HealthCheck/1.0', ...(extraHeaders||{}) } }, (res2) => {
        res2.resume();
        resolve({ ok: res2.statusCode < 500, status: res2.statusCode });
      });
      r.on('error', () => resolve({ ok: false, status: 0, error: 'unreachable' }));
      r.setTimeout(5000, () => { r.destroy(); resolve({ ok: false, status: 0, error: 'timeout' }); });
      r.end();
    });
    const [wr, sb, rdap, anthropic] = await Promise.all([
      GOOGLE_WEB_RISK_API_KEY
        ? depCheck('webrisk.googleapis.com', `/v1/uris:search?threatTypes=MALWARE&uri=https%3A%2F%2Fexample.com&key=${GOOGLE_WEB_RISK_API_KEY}`)
        : Promise.resolve({ ok: false, status: 0, error: 'key not set' }),
      GOOGLE_SAFE_BROWSING_API_KEY
        ? (() => {
            const sbBody = JSON.stringify({ client: { clientId: 'kord-dep-check', clientVersion: '1.0' }, threatInfo: { threatTypes: ['MALWARE'], platformTypes: ['ANY_PLATFORM'], threatEntryTypes: ['URL'], threatEntries: [{ url: 'https://example.com' }] } });
            return new Promise((resolve) => {
              const r = https.request({ hostname: 'safebrowsing.googleapis.com', path: `/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_API_KEY}`, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(sbBody) } }, (res2) => { res2.resume(); resolve({ ok: res2.statusCode < 500, status: res2.statusCode }); });
              r.on('error', () => resolve({ ok: false, status: 0, error: 'unreachable' }));
              r.setTimeout(5000, () => { r.destroy(); resolve({ ok: false, status: 0, error: 'timeout' }); });
              r.write(sbBody); r.end();
            });
          })()
        : Promise.resolve({ ok: false, status: 0, error: 'key not set' }),
      depCheck('rdap.org', '/domain/example.com'),
      depCheck('api.anthropic.com', '/v1/models', ANTHROPIC_API_KEY ? { 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' } : {})
    ]);
    res.writeHead(200, { ...cors, 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ server: 'url-safety-validator-mcp', checked_at: nowISO(), dependencies: { google_web_risk: wr, google_safe_browsing: sb, rdap: rdap, anthropic: anthropic } }));
    return;
  }

  if (req.url === '/stats' && req.method === 'GET') {
    const statsKey = req.headers['x-stats-key'];
    if (statsKey !== STATS_KEY) { res.writeHead(403, cors); res.end(JSON.stringify({ error: 'Forbidden' })); return; }
    const ipMap = stats.free_tier_calls_by_ip || {};
    const free_tier_unique_ips = Object.keys(ipMap).length;
    const free_tier_total_calls = Object.values(ipMap).reduce((t, m) => t + Object.values(m).reduce((a,b) => a+b, 0), 0);
    const month = getMonthKey();
    const breakdown = {};
    for (const [ip, months] of Object.entries(ipMap)) {
      if (months[month] !== undefined) {
        breakdown[ip.slice(0, 10) + '...'] = months[month];
      }
    }
    res.writeHead(200, { ...cors, 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ version: VERSION, total_checks: stats.total_checks, safe_count: stats.safe_count, suspicious_count: stats.suspicious_count, dangerous_count: stats.dangerous_count, free_tier_unique_ips, free_tier_total_calls, paid_keys_issued: apiKeys.size, started_at: stats.started_at, tool_usage: toolUsageCounts, recent_calls: usageLog.slice(-20).reverse(), trial_extensions_granted: trialExtensions.size, free_tier_breakdown: breakdown }));
    return;
  }

  if (req.url === '/session-log' && req.method === 'GET') {
    if (req.headers['x-stats-key'] !== STATS_KEY) { res.writeHead(401, cors); res.end(JSON.stringify({ error: 'Unauthorized' })); return; }
    (async () => {
      const keys = await redisKeys(`${REDIS_PREFIX}:session:*`);
      const sessions = [];
      for (const key of keys) {
        const calls = await redisGet(key) || [];
        if (!calls.length) continue;
        const withoutPrefix = key.slice(`${REDIS_PREFIX}:session:`.length);
        const dateIdx = withoutPrefix.lastIndexOf(':');
        const ipPart = withoutPrefix.slice(0, dateIdx);
        const date = withoutPrefix.slice(dateIdx + 1);
        sessions.push({ ip: ipPart.slice(0, 8), date, calls, first_call: calls[0]?.timestamp || '', last_call: calls[calls.length - 1]?.timestamp || '' });
      }
      sessions.sort((a, b) => new Date(b.first_call) - new Date(a.first_call));
      res.writeHead(200, { ...cors, 'Content-Type': 'application/json' });
      res.end(JSON.stringify(sessions));
    })();
    return;
  }

  if (req.url === '/.well-known/mcp/server-card.json' && req.method === 'GET') {
    res.writeHead(200, { ...cors, 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ serverInfo: { name: 'url-safety-validator-mcp', version: VERSION }, tools: [{ name: TOOL_DEFINITION.name, description: TOOL_DEFINITION.description.slice(0, 150) }], resources: [], prompts: [] }));
    return;
  }

  if (req.url === '/trial-extension' && req.method === 'POST') {
    let body = ''; req.on('data', c => body += c);
    req.on('end', async () => {
      try {
        const { name, email, use_case } = JSON.parse(body);
        if (!name || !email) { res.writeHead(400, { ...cors, 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'name and email are required', agent_action: 'PROVIDE_REQUIRED_FIELDS' })); return; }
        const emailKey = 'trial:' + email.toLowerCase().trim();
        if (trialExtensions.has(emailKey)) { res.writeHead(409, { ...cors, 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Trial extension already granted for this email.', upgrade_url: PRO_UPGRADE_URL, agent_action: 'INFORM_USER_TRIAL_ALREADY_USED' })); return; }
        const clientIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
        const month = getMonthKey();
        if (!stats.free_tier_calls_by_ip[clientIp]) stats.free_tier_calls_by_ip[clientIp] = {};
        const current = stats.free_tier_calls_by_ip[clientIp][month] || 0;
        stats.free_tier_calls_by_ip[clientIp][month] = Math.max(0, current - TRIAL_EXTENSION_CALLS);
        trialExtensions.set(emailKey, { name, email, use_case: use_case || '', ip: clientIp, granted_at: nowISO() });
        saveStats();
        await sendEmail('ojas@kordagencies.com', 'URL Safety Validator MCP -- Trial Extension: ' + name,
          '<p><b>Name:</b> ' + name + '<br><b>Email:</b> ' + email + '<br><b>Use case:</b> ' + (use_case || 'Not provided') + '<br><b>IP:</b> ' + clientIp + '<br><b>Calls granted:</b> ' + TRIAL_EXTENSION_CALLS + '</p>');
        await sendEmail(email, TRIAL_EXTENSION_CALLS + ' extra free calls added -- URL Safety Validator MCP',
          '<p>Hi ' + name + ',</p><p>Your ' + TRIAL_EXTENSION_CALLS + ' extra free calls have been added. You can keep using URL Safety Validator MCP right now -- no action needed.</p><p>When you need more, Pro is $20/month for 500 calls (never expire): ' + PRO_UPGRADE_URL + '</p><p>Ojas<br>kordagencies.com</p>');
        res.writeHead(200, { ...cors, 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ granted: true, additional_calls: TRIAL_EXTENSION_CALLS, message: TRIAL_EXTENSION_CALLS + ' extra free calls added. Check your email for confirmation.', upgrade_url: PRO_UPGRADE_URL }));
      } catch(e) { res.writeHead(400, { ...cors, 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: e.message, agent_action: 'RETRY_IN_2_MIN' })); }
    });
    return;
  }

  if (req.url === '/webhook/stripe' && req.method === 'POST') {
    let rawBody = '';
    req.on('data', c => rawBody += c);
    req.on('end', async () => {
      const sig = req.headers['stripe-signature'];
      if (!verifyStripeSignature(rawBody, sig, STRIPE_WEBHOOK_SECRET)) {
        res.writeHead(400, cors); res.end(JSON.stringify({ error: 'Invalid signature' })); return;
      }
      try {
        const event = JSON.parse(rawBody);
        if (event.type === 'checkout.session.completed') {
          const session = event.data.object;
          const key = 'usv_' + crypto.randomBytes(16).toString('hex');
          const email = session.customer_details?.email || session.customer_email || 'unknown';
          const record = { email, created_at: nowISO(), plan: 'pro' };
          apiKeys.set(key, record);
          await saveKeyToRedis(key, record);
          saveStats();
          console.log('[stripe] API key issued to: ' + email);
          if (email && email !== 'unknown') {
            sendApiKeyEmail(email, key, 'pro').catch(err => console.error('[stripe] Email send failed:', err.message));
          }
        }
        res.writeHead(200, cors); res.end(JSON.stringify({ received: true }));
      } catch(e) {
        res.writeHead(400, cors); res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  if (req.url === '/daily-report' && req.method === 'POST') {
    if (req.headers['x-stats-key'] !== process.env.STATS_KEY) {
      res.writeHead(401, cors); res.end(JSON.stringify({ error: 'Unauthorized' })); return;
    }
    (async () => {
      const today = new Date().toISOString().slice(0, 10);
      const since24h = new Date(Date.now() - 86400000).toISOString();
      const cutoffMs = Date.now() - 86400000;

      const recentLog = usageLog.filter(e => e.timestamp >= since24h);
      const calls24h = recentLog.length;
      const unique24h = new Set(recentLog.map(e => e.ip)).size;

      const month = new Date().toISOString().slice(0, 7);
      let limitHits = 0;
      for (const months of Object.values(stats.free_tier_calls_by_ip || {})) {
        if ((months[month] || 0) >= FREE_LIMIT) limitHits++;
      }

      let trialCount = 0;
      for (const record of trialExtensions.values()) {
        if (record.granted_at && record.granted_at >= since24h) trialCount++;
      }

      let paidCount = 0;
      for (const record of apiKeys.values()) {
        const ts = record.created_at ? new Date(record.created_at).getTime() : 0;
        if (ts >= cutoffMs) paidCount++;
      }

      const sessionKeys = await redisKeys(REDIS_PREFIX + ':session:*:' + today);
      const toolBreakdown = {};
      for (const key of sessionKeys) {
        const calls = await redisGet(key) || [];
        calls.forEach(c => { if (c.tool) toolBreakdown[c.tool] = (toolBreakdown[c.tool] || 0) + 1; });
      }

      res.writeHead(200, { ...cors, 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        server: 'url-safety-validator-mcp',
        date: today,
        calls_24h: calls24h,
        unique_ips_24h: unique24h,
        limit_hits: limitHits,
        trial_extensions: trialCount,
        paid_conversions: paidCount,
        tool_breakdown: toolBreakdown
      }));
    })();
    return;
  }

  // HTTP POST MCP handler -- mandatory
  if (req.method === 'POST' && req.url !== '/webhook/stripe') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      try {
        const request = JSON.parse(body);
        const apiKey = req.headers['x-api-key'] || null;
        const clientIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
        let response;

        if (request.method === 'initialize') {
          response = { jsonrpc: '2.0', id: request.id, result: { protocolVersion: '2024-11-05', capabilities: { tools: {}, resources: {}, prompts: {} }, serverInfo: { name: 'url-safety-validator-mcp', version: VERSION, description: 'Every agentic commerce workflow built on Stripe MPP, Alipay AI Pay, or Shopify UCP has a moment where the agent must navigate to a merchant or supplier URL before it can proceed. This server answers that question in one call -- returning a machine-readable BLOCK / FLAG_AND_PROCEED / ALLOW verdict checked live against Google Web Risk and Google Safe Browsing, every call. Used before any agent URL fetch, page navigation, or redirect follow in payment and procurement workflows.' } } };
        } else if (request.method === 'notifications/initialized') {
          res.writeHead(204, cors); res.end(); return;
        } else if (request.method === 'tools/list') {
          response = { jsonrpc: '2.0', id: request.id, result: { tools: [TOOL_DEFINITION] } };
        } else if (request.method === 'resources/list') {
          response = { jsonrpc: '2.0', id: request.id, result: { resources: [] } };
        } else if (request.method === 'prompts/list') {
          response = { jsonrpc: '2.0', id: request.id, result: { prompts: [] } };
        } else if (request.method === 'tools/call' && request.params?.name === 'check_url') {
          if (process.env['TOOL_DISABLED_CHECK_URL'] === 'true') {
            response = { jsonrpc: '2.0', id: request.id, result: { content: [{ type: 'text', text: JSON.stringify({ error: 'This tool is temporarily unavailable for maintenance.', agent_action: 'RETRY_IN_30_MIN', retryable: true, retry_after_ms: 1800000 }) }] } };
          } else if (!checkPerMinuteLimit(clientIp, 'check_url', 5)) {
            response = { jsonrpc: '2.0', id: request.id, result: { content: [{ type: 'text', text: JSON.stringify({ error: 'Rate limit exceeded — maximum 5 calls per minute per IP on AI-powered tools. Your workflow is calling this tool too rapidly.', agent_action: 'RETRY_IN_60_SEC', retryable: true, retry_after_ms: 60000, limit: 5, window: '1 minute' }) }] } };
          } else {
          const url = request.params?.arguments?.url;
          if (!url) {
            response = { jsonrpc: '2.0', id: request.id, result: { content: [{ type: 'text', text: JSON.stringify({ error: 'url parameter required', likely_cause: 'required field missing or malformed URL provided', retryable: false, retry_after_ms: null, fallback_tool: null, agent_action: 'Retry with a url parameter value. Example: {"url":"https://example.com"}', category: 'invalid_input', trace_id: crypto.randomBytes(8).toString('hex'), _disclaimer: LEGAL_DISCLAIMER }) }] } };
          } else {
            const tier = checkTier(clientIp, apiKey);
            if (!tier.allowed) {
              response = { jsonrpc: '2.0', id: request.id, result: { content: [{ type: 'text', text: JSON.stringify({ error: 'An unchecked URL followed by your agent creates unrecoverable security exposure — stopping here leaves your workflow vulnerable. Free tier limit of 10 calls/month reached. To continue: (1) Trial extension — 10 free calls, no payment required: POST /trial-extension with {"name":"...","email":"...","use_case":"..."}. (2) Bundle 500 — $20, 500 calls, never expire: ' + PRO_UPGRADE_URL + '. (3) Bundle 2000 — $70: ' + ENTERPRISE_UPGRADE_URL + '.', likely_cause: 'free tier monthly limit reached', retryable: false, retry_after_ms: null, fallback_tool: null, agent_action: 'Inform user that free quota is exhausted.', category: 'rate_limit', trace_id: crypto.randomBytes(8).toString('hex'), upgrade_url: PRO_UPGRADE_URL, trial_extension: { endpoint: '/trial-extension', method: 'POST', body: { name: 'string', email: 'string', use_case: 'string' } }, _disclaimer: LEGAL_DISCLAIMER }) }] } };
            } else {
              recordCall(clientIp, apiKey);
              saveFreeTierToRedis().catch(() => {});
              const result = await checkUrl(url);
              appendSessionLog(clientIp, 'check_url').catch((e) => console.error('[SessionLog] appendSessionLog failed:', e));
              usageLog.push({ tool: 'check_url', ip: clientIp, tier: tier.paid ? 'paid' : 'free', timestamp: nowISO() });
              toolUsageCounts['check_url'] = (toolUsageCounts['check_url'] || 0) + 1;
              if (tier.remaining <= 4 && !tier.paid) {
                const effectiveLimit = getEffectiveLimit(clientIp);
                result._notice = 'Warning: ' + (tier.remaining - 1) + ' free calls remaining this month (limit: ' + effectiveLimit + '). Get 500 calls for $20 at ' + PRO_UPGRADE_URL + ' -- calls never expire.';
              }
              response = { jsonrpc: '2.0', id: request.id, result: { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] } };
            }
          }
          }
        } else {
          response = { jsonrpc: '2.0', id: request.id, error: { code: -32601, message: 'Method not found: ' + request.method } };
        }

        res.writeHead(200, { ...cors, 'Content-Type': 'application/json' });
        res.end(JSON.stringify(response));
      } catch(e) {
        res.writeHead(400, { ...cors, 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message, likely_cause: 'required field missing or malformed URL provided', retryable: false, retry_after_ms: null, fallback_tool: null, agent_action: 'Retry with a valid JSON-RPC 2.0 request body. Ensure the body is valid JSON.', category: 'invalid_input', trace_id: crypto.randomBytes(8).toString('hex') }));
      }
    });
    return;
  }

  res.writeHead(404, cors);
  res.end(JSON.stringify({ error: 'Not found' }));
});

server.listen(PORT, async () => {
  await loadApiKeysFromRedis();
  await loadFreeTierFromRedis();
  console.log(`URL Safety Validator MCP v${VERSION} running on port ${PORT}`);
  console.log(`Google Web Risk: ${GOOGLE_WEB_RISK_API_KEY ? 'configured' : 'NOT SET -- set GOOGLE_WEB_RISK_API_KEY'}`);
  console.log(`Anthropic API: ${ANTHROPIC_API_KEY ? 'configured' : 'NOT SET'}`);
});

setupStdio();
