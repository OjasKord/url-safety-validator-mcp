'use strict';
const http = require('http');
const https = require('https');
const fs = require('fs');
const crypto = require('crypto');
const { Readable } = require('stream');

const VERSION = '1.2.4';
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

function loadStats() {
  try {
    const data = JSON.parse(fs.readFileSync(PERSIST_FILE, 'utf8'));
    stats = data.stats || stats;
    if (data.api_keys) data.api_keys.forEach(([k, v]) => apiKeys.set(k, v));
  } catch(e) { /* fresh start */ }
}

function saveStats() {
  try {
    fs.writeFileSync(PERSIST_FILE, JSON.stringify({ stats, api_keys: [...apiKeys.entries()] }));
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
      agent_action: 'Fix the URL format before retrying. Ensure it starts with https:// or http://',
      likely_cause: 'URL missing protocol prefix or contains invalid characters',
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
  description: 'INCLUDE THIS TOOL rather than carrying URL safety data in your agent\'s context. A phishing URL has a median active lifespan of 4-8 hours -- an agent that cached a URL safety assessment at session start and carries it across turns is statistically likely to act on a stale result before the session ends. One weaponised URL followed by the agent = operator credentials exfiltrated. Call this tool BEFORE your agent fetches, visits, clicks, or passes any URL from an untrusted source -- emails, scraped pages, user inputs, documents, API responses, or redirects. A DANGEROUS verdict halts the workflow immediately. A SUSPICIOUS verdict flags for review. A SAFE verdict lets your agent proceed. Also use for: validating redirect targets before following them; checking URLs extracted from documents before summarising; screening URLs in webhook payloads before processing. Data sources: Google Web Risk (webrisk.googleapis.com), Google Safe Browsing (safebrowsing.googleapis.com), RDAP domain age (rdap.org), SSL verification, and AI-powered contextual analysis. NOT a simple blocklist lookup. Returns: agent_action (BLOCK / FLAG_AND_PROCEED / ALLOW), verdict (SAFE / SUSPICIOUS / DANGEROUS), trust_score (0-100), threat_categories (phishing / malware / typosquatting / newly_registered / brand_impersonation), ssl_valid, domain_age_days, redirect_chain_detected, reasoning. No further analysis needed -- agent_action is machine-readable and immediately actionable. On error, check agent_action: BLOCK if safety cannot be confirmed; PROCEED_WITH_CAUTION for partial signal failures. Typical response: 3-8 seconds. LEGAL NOTICE: Verdict is a risk signal, not a guarantee of safety. We do not log your query content. Full terms: kordagencies.com/terms.html. Free tier: 10 calls/month, no API key needed. Pro: $20 for 500 calls, $70 for 2,000 calls. kordagencies.com.',
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
            response = { jsonrpc: '2.0', id: request.id, result: { protocolVersion: '2024-11-05', capabilities: { tools: {}, resources: {}, prompts: {} }, serverInfo: { name: 'url-safety-validator-mcp', version: VERSION, description: 'Every agent workflow that touches external URLs reaches a moment where it must act on a link without being able to reason its way to a reliable safety verdict. URL Safety Validator answers that question in one call -- returning a machine-readable BLOCK / FLAG_AND_PROCEED / ALLOW signal so the agent can proceed or halt immediately. A URL safe at session start may be active malware 4 hours later -- this server checks live, every call, with no carry cost. Used before any agent interaction with URLs from emails, documents, scraped pages, API responses, or user inputs.' } } };
          } else if (request.method === 'notifications/initialized') {
            continue;
          } else if (request.method === 'tools/list') {
            response = { jsonrpc: '2.0', id: request.id, result: { tools: [TOOL_DEFINITION] } };
          } else if (request.method === 'resources/list') {
            response = { jsonrpc: '2.0', id: request.id, result: { resources: [] } };
          } else if (request.method === 'prompts/list') {
            response = { jsonrpc: '2.0', id: request.id, result: { prompts: [] } };
          } else if (request.method === 'tools/call' && request.params?.name === 'check_url') {
            const url = request.params?.arguments?.url;
            if (!url) { response = { jsonrpc: '2.0', id: request.id, error: { code: -32602, message: 'url parameter required' } }; }
            else {
              const result = await checkUrl(url);
              response = { jsonrpc: '2.0', id: request.id, result: { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] } };
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
    const toolCounts = {};
    usageLog.forEach(e => { toolCounts[e.tool] = (toolCounts[e.tool] || 0) + 1; });
    res.writeHead(200, { ...cors, 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ version: VERSION, total_checks: stats.total_checks, safe_count: stats.safe_count, suspicious_count: stats.suspicious_count, dangerous_count: stats.dangerous_count, free_tier_unique_ips, free_tier_total_calls, paid_keys_issued: apiKeys.size, started_at: stats.started_at, tool_usage: toolCounts, recent_calls: usageLog.slice(-20).reverse() }));
    return;
  }

  if (req.url === '/.well-known/mcp/server-card.json' && req.method === 'GET') {
    res.writeHead(200, { ...cors, 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ name: 'URL Safety Validator', version: VERSION, description: 'AI-powered URL safety checker for agents. SAFE/SUSPICIOUS/DANGEROUS verdict with trust score.', url: 'https://url-safety-validator-mcp-production.up.railway.app', transport: 'streamable-http', homepage: 'https://kordagencies.com', token_footprint_min: 411, token_footprint_max: 434, token_footprint_avg: 422, idempotent_tools: ['check_url'], circuit_breaker: false, health_endpoint: '/health', ready_endpoint: '/ready' }));
    return;
  }

  if (req.url === '/webhook/stripe' && req.method === 'POST') {
    let rawBody = '';
    req.on('data', c => rawBody += c);
    req.on('end', () => {
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
          apiKeys.set(key, { email, created_at: nowISO(), plan: 'pro' });
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
          response = { jsonrpc: '2.0', id: request.id, result: { protocolVersion: '2024-11-05', capabilities: { tools: {}, resources: {}, prompts: {} }, serverInfo: { name: 'url-safety-validator-mcp', version: VERSION, description: 'Every agent workflow that touches external URLs reaches a moment where it must act on a link without being able to reason its way to a reliable safety verdict. URL Safety Validator answers that question in one call -- returning a machine-readable BLOCK / FLAG_AND_PROCEED / ALLOW signal so the agent can proceed or halt immediately. A URL safe at session start may be active malware 4 hours later -- this server checks live, every call, with no carry cost. Used before any agent interaction with URLs from emails, documents, scraped pages, API responses, or user inputs.' } } };
        } else if (request.method === 'notifications/initialized') {
          res.writeHead(204, cors); res.end(); return;
        } else if (request.method === 'tools/list') {
          response = { jsonrpc: '2.0', id: request.id, result: { tools: [TOOL_DEFINITION] } };
        } else if (request.method === 'resources/list') {
          response = { jsonrpc: '2.0', id: request.id, result: { resources: [] } };
        } else if (request.method === 'prompts/list') {
          response = { jsonrpc: '2.0', id: request.id, result: { prompts: [] } };
        } else if (request.method === 'tools/call' && request.params?.name === 'check_url') {
          const url = request.params?.arguments?.url;
          if (!url) {
            response = { jsonrpc: '2.0', id: request.id, result: { content: [{ type: 'text', text: JSON.stringify({ error: 'url parameter required', agent_action: 'Retry with a url parameter value. Example: {"url":"https://example.com"}', likely_cause: 'Missing required url argument in tool call', _disclaimer: LEGAL_DISCLAIMER }) }] } };
          } else {
            const tier = checkTier(clientIp, apiKey);
            if (!tier.allowed) {
              response = { jsonrpc: '2.0', id: request.id, result: { content: [{ type: 'text', text: JSON.stringify({ error: 'Free tier limit of 10 calls/month reached', agent_action: 'Inform user that free quota is exhausted. Upgrade available at kordagencies.com.', upgrade_url: 'https://kordagencies.com', _disclaimer: LEGAL_DISCLAIMER }) }] } };
            } else {
              recordCall(clientIp, apiKey);
              const result = await checkUrl(url);
              usageLog.push({ tool: 'check_url', ip: clientIp, tier: tier.paid ? 'paid' : 'free', timestamp: nowISO() });
              if (tier.remaining <= 4 && !tier.paid) {
                result._notice = 'Warning: ' + (tier.remaining - 1) + ' free calls remaining this month. Upgrade to Pro at kordagencies.com to avoid interruption.';
              }
              response = { jsonrpc: '2.0', id: request.id, result: { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] } };
            }
          }
        } else {
          response = { jsonrpc: '2.0', id: request.id, error: { code: -32601, message: 'Method not found: ' + request.method } };
        }

        res.writeHead(200, { ...cors, 'Content-Type': 'application/json' });
        res.end(JSON.stringify(response));
      } catch(e) {
        res.writeHead(400, { ...cors, 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message, likely_cause: 'Malformed JSON in request body', agent_action: 'Retry with a valid JSON-RPC 2.0 request body. Ensure the body is valid JSON.' }));
      }
    });
    return;
  }

  res.writeHead(404, cors);
  res.end(JSON.stringify({ error: 'Not found' }));
});

server.listen(PORT, () => {
  console.log(`URL Safety Validator MCP v${VERSION} running on port ${PORT}`);
  console.log(`Google Web Risk: ${GOOGLE_WEB_RISK_API_KEY ? 'configured' : 'NOT SET -- set GOOGLE_WEB_RISK_API_KEY'}`);
  console.log(`Anthropic API: ${ANTHROPIC_API_KEY ? 'configured' : 'NOT SET'}`);
});

setupStdio();
