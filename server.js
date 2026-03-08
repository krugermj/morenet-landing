const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const APP_URL = process.env.APP_URL || 'https://nex.morenet.co.za';

// ── Authentik OIDC Config ────────────────────────────────
const AUTHENTIK_URL = process.env.AUTHENTIK_URL || '';
const AUTHENTIK_CLIENT_ID = process.env.AUTHENTIK_CLIENT_ID || '';
const AUTHENTIK_CLIENT_SECRET = process.env.AUTHENTIK_CLIENT_SECRET || '';
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || 'marius@morenet.co.za').split(',').map(e => e.trim().toLowerCase());
const ADMIN_GROUP = process.env.ADMIN_GROUP || 'NEX Admins';
const OIDC_ENABLED = !!(AUTHENTIK_URL && AUTHENTIK_CLIENT_ID && AUTHENTIK_CLIENT_SECRET);

// OIDC endpoints
const OIDC_AUTH_URL = `${AUTHENTIK_URL}/application/o/authorize/`;
const OIDC_TOKEN_URL = `${AUTHENTIK_URL}/application/o/token/`;
const OIDC_USERINFO_URL = `${AUTHENTIK_URL}/application/o/userinfo/`;
const OIDC_CALLBACK_URL = `${APP_URL}/auth/callback`;

if (OIDC_ENABLED) {
  console.log(`Authentik OIDC enabled: ${AUTHENTIK_URL}`);
} else {
  console.log('Authentik OIDC not configured — local auth fallback active');
}

// ── Local Auth Fallback (dev/testing only) ───────────────
const LOCAL_AUTH_ENABLED = !OIDC_ENABLED;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@morenet.co.za';
const ADMIN_PASS = process.env.ADMIN_PASS || 'changeme';
let bcrypt = null;
if (LOCAL_AUTH_ENABLED) {
  try { bcrypt = require('bcryptjs'); } catch { console.warn('bcryptjs not available — local auth disabled'); }
}

// ── User Store ───────────────────────────────────────────
const DATA_FILE = process.env.DATA_FILE || '/app/data/users.json';

function loadUsers() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    }
  } catch (e) { console.error('Error loading users:', e.message); }
  return [];
}

function saveUsers(users) {
  const dir = path.dirname(DATA_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(DATA_FILE, JSON.stringify(users, null, 2));
}

let users = loadUsers();

// Seed local admin for fallback mode
if (LOCAL_AUTH_ENABLED && bcrypt && !users.find(u => u.email === ADMIN_EMAIL)) {
  users.push({
    id: 1, email: ADMIN_EMAIL, password: bcrypt.hashSync(ADMIN_PASS, 10),
    name: 'Admin', role: 'admin', auth: 'local',
    created_at: new Date().toISOString(), last_login: null
  });
  saveUsers(users);
  console.log(`Local admin seeded: ${ADMIN_EMAIL}`);
}

// ── Rate Limiter ─────────────────────────────────────────
const loginAttempts = new Map();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000;
const MAX_ATTEMPTS = 10;
const LOCKOUT_DURATION = 15 * 60 * 1000;

function rateLimitCheck(ip) {
  const now = Date.now();
  const record = loginAttempts.get(ip);
  if (!record) return { allowed: true };
  if (record.lockedUntil && now < record.lockedUntil) {
    return { allowed: false, remaining: Math.ceil((record.lockedUntil - now) / 1000 / 60) };
  }
  if (now - record.firstAttempt > RATE_LIMIT_WINDOW) { loginAttempts.delete(ip); return { allowed: true }; }
  if (record.count >= MAX_ATTEMPTS) {
    record.lockedUntil = now + LOCKOUT_DURATION;
    return { allowed: false, remaining: Math.ceil(LOCKOUT_DURATION / 1000 / 60) };
  }
  return { allowed: true };
}

function rateLimitRecord(ip) {
  const now = Date.now();
  const record = loginAttempts.get(ip) || { count: 0, firstAttempt: now };
  record.count++;
  loginAttempts.set(ip, record);
}

function rateLimitReset(ip) { loginAttempts.delete(ip); }

setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of loginAttempts) {
    if (now - record.firstAttempt > RATE_LIMIT_WINDOW * 2) loginAttempts.delete(ip);
  }
}, 30 * 60 * 1000);

// ── Middleware ────────────────────────────────────────────
app.set('trust proxy', true);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

function resolveRole(email, authentikGroups) {
  // Check Authentik groups first
  if (authentikGroups && authentikGroups.includes(ADMIN_GROUP)) return 'admin';
  // Check admin email list
  if (ADMIN_EMAILS.includes(email.toLowerCase())) return 'admin';
  // Check local store
  users = loadUsers();
  const existing = users.find(u => u.email === email.toLowerCase());
  if (existing) return existing.role;
  return 'user';
}

function upsertUser(email, name, groups, authMethod) {
  users = loadUsers();
  let user = users.find(u => u.email === email.toLowerCase());
  const role = resolveRole(email, groups);

  if (user) {
    user.name = name || user.name;
    user.role = role;
    user.last_login = new Date().toISOString();
    user.auth = authMethod;
    if (groups) user.groups = groups;
  } else {
    user = {
      id: Math.max(...users.map(u => u.id), 0) + 1,
      email: email.toLowerCase().trim(),
      name: name || '',
      role,
      auth: authMethod,
      groups: groups || [],
      created_at: new Date().toISOString(),
      last_login: new Date().toISOString()
    };
    users.push(user);
  }
  saveUsers(users);
  return user;
}

function authMiddleware(req, res, next) {
  const token = req.cookies.nex_token;
  if (!token) return res.redirect('/login');
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.clearCookie('nex_token');
    return res.redirect('/login');
  }
}

function apiAuthMiddleware(req, res, next) {
  const token = req.cookies.nex_token;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.clearCookie('nex_token');
    return res.status(401).json({ error: 'Session expired' });
  }
}

function adminMiddleware(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}

function issueToken(res, user) {
  const token = jwt.sign(
    { id: user.id, email: user.email, name: user.name, role: user.role },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
  res.cookie('nex_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

// ── Health Check ─────────────────────────────────────────
app.get('/health', (req, res) => res.json({
  status: 'ok', port: PORT, auth: OIDC_ENABLED ? 'authentik' : 'local'
}));

// ── Public assets ────────────────────────────────────────
app.get('/login/logo.png', (req, res) => res.sendFile(path.join(__dirname, 'public', 'logo.png')));
app.get('/login/nex.png', (req, res) => res.sendFile(path.join(__dirname, 'public', 'nex.png')));
app.get('/admin/logo.png', (req, res) => res.sendFile(path.join(__dirname, 'public', 'logo.png')));
app.get('/admin/nex.png', (req, res) => res.sendFile(path.join(__dirname, 'public', 'nex.png')));

// ── Login Page ───────────────────────────────────────────
app.get('/login', (req, res) => {
  const token = req.cookies.nex_token;
  if (token) {
    try { jwt.verify(token, JWT_SECRET); return res.redirect('/'); } catch {}
  }

  if (OIDC_ENABLED) {
    // Show Authentik login button
    res.sendFile(path.join(__dirname, 'views', 'login.html'));
  } else {
    // Show local login form (dev fallback)
    res.sendFile(path.join(__dirname, 'views', 'login-local.html'));
  }
});

// ── Authentik OIDC Flow ──────────────────────────────────
app.get('/auth/start', (req, res) => {
  if (!OIDC_ENABLED) return res.redirect('/login');

  const ip = req.ip;
  const rateCheck = rateLimitCheck(ip);
  if (!rateCheck.allowed) {
    return res.status(429).send(`Too many attempts. Try again in ${rateCheck.remaining} minutes.`);
  }

  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');

  // Store state + nonce in a short-lived cookie
  res.cookie('oidc_state', JSON.stringify({ state, nonce }), {
    httpOnly: true, secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax', maxAge: 10 * 60 * 1000 // 10 minutes
  });

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: AUTHENTIK_CLIENT_ID,
    redirect_uri: OIDC_CALLBACK_URL,
    scope: 'openid email profile',
    state,
    nonce,
  });

  res.redirect(`${OIDC_AUTH_URL}?${params}`);
});

app.get('/auth/callback', async (req, res) => {
  if (!OIDC_ENABLED) return res.redirect('/login');

  const ip = req.ip;
  const rateCheck = rateLimitCheck(ip);
  if (!rateCheck.allowed) {
    return res.status(429).send(`Too many attempts. Try again in ${rateCheck.remaining} minutes.`);
  }

  const { code, state } = req.query;
  if (!code || !state) {
    rateLimitRecord(ip);
    return res.redirect('/login?error=missing_params');
  }

  // Verify state
  let storedState;
  try {
    storedState = JSON.parse(req.cookies.oidc_state || '{}');
  } catch { storedState = {}; }

  if (state !== storedState.state) {
    rateLimitRecord(ip);
    return res.redirect('/login?error=invalid_state');
  }

  res.clearCookie('oidc_state');

  try {
    // Exchange code for tokens
    const tokenRes = await fetch(OIDC_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: OIDC_CALLBACK_URL,
        client_id: AUTHENTIK_CLIENT_ID,
        client_secret: AUTHENTIK_CLIENT_SECRET,
      }),
    });

    if (!tokenRes.ok) {
      console.error('Token exchange failed:', tokenRes.status, await tokenRes.text());
      rateLimitRecord(ip);
      return res.redirect('/login?error=token_failed');
    }

    const tokenData = await tokenRes.json();

    // Fetch userinfo
    const userRes = await fetch(OIDC_USERINFO_URL, {
      headers: { 'Authorization': `Bearer ${tokenData.access_token}` },
    });

    if (!userRes.ok) {
      console.error('Userinfo failed:', userRes.status, await userRes.text());
      rateLimitRecord(ip);
      return res.redirect('/login?error=userinfo_failed');
    }

    const userInfo = await userRes.json();
    const email = (userInfo.email || '').toLowerCase().trim();
    const name = userInfo.name || userInfo.preferred_username || email.split('@')[0];
    const groups = userInfo.groups || [];

    if (!email) {
      return res.redirect('/login?error=no_email');
    }

    // Upsert user and issue session token
    const user = upsertUser(email, name, groups, 'authentik');
    issueToken(res, user);
    rateLimitReset(ip);

    console.log(`OIDC login: ${email} (role: ${user.role})`);
    res.redirect('/');

  } catch (err) {
    console.error('OIDC callback error:', err);
    rateLimitRecord(ip);
    return res.redirect('/login?error=server_error');
  }
});

// ── Local Auth Fallback (dev only) ───────────────────────
if (LOCAL_AUTH_ENABLED && bcrypt) {
  app.post('/api/login', (req, res) => {
    const ip = req.ip;
    const rateCheck = rateLimitCheck(ip);
    if (!rateCheck.allowed) {
      return res.status(429).json({ error: `Too many attempts. Try again in ${rateCheck.remaining} minutes.` });
    }

    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    users = loadUsers();
    const user = users.find(u => u.email === email.toLowerCase().trim());
    if (!user || !user.password || !bcrypt.compareSync(password, user.password)) {
      rateLimitRecord(ip);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    user.last_login = new Date().toISOString();
    saveUsers(users);
    rateLimitReset(ip);
    issueToken(res, user);
    res.json({ success: true, name: user.name, role: user.role });
  });
}

// ── Logout ───────────────────────────────────────────────
app.post('/api/logout', (req, res) => {
  res.clearCookie('nex_token');
  res.json({ success: true });
});

app.get('/logout', (req, res) => {
  res.clearCookie('nex_token');
  res.redirect('/login');
});

// ── Admin API ────────────────────────────────────────────
app.get('/admin', authMiddleware, adminMiddleware, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});

app.get('/api/auth-info', apiAuthMiddleware, (req, res) => {
  res.json({ mode: OIDC_ENABLED ? 'authentik' : 'local', authentikUrl: AUTHENTIK_URL || null });
});

app.get('/api/users', apiAuthMiddleware, adminMiddleware, (req, res) => {
  users = loadUsers();
  const safeUsers = users.map(u => ({
    id: u.id, email: u.email, name: u.name, role: u.role,
    auth: u.auth || 'local', groups: u.groups || [],
    created_at: u.created_at, last_login: u.last_login
  }));
  res.json(safeUsers);
});

app.put('/api/users/:id', apiAuthMiddleware, adminMiddleware, (req, res) => {
  const userId = parseInt(req.params.id);
  users = loadUsers();
  const user = users.find(u => u.id === userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const { name, role } = req.body;
  if (name !== undefined) user.name = name;
  if (role !== undefined) {
    if (userId === req.user.id && role !== 'admin') {
      return res.status(400).json({ error: 'Cannot remove your own admin role' });
    }
    user.role = role;
  }
  saveUsers(users);
  res.json({ success: true });
});

app.delete('/api/users/:id', apiAuthMiddleware, adminMiddleware, (req, res) => {
  const userId = parseInt(req.params.id);
  if (userId === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
  users = loadUsers();
  users = users.filter(u => u.id !== userId);
  saveUsers(users);
  res.json({ success: true });
});

// ── Sherpa Chat (AI Assistant) ────────────────────────────
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || '';
const SHERPA_MODEL = process.env.SHERPA_MODEL || 'google/gemini-2.0-flash-001';
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_ADMIN_CHAT_ID = process.env.TELEGRAM_ADMIN_CHAT_ID || '';

const SHERPA_SYSTEM = `You are NEX, a client insights specialist for MoreNET / ICTInternet. You help service desk agents and staff by cross-referencing ALL available systems to build a complete picture.

## Your Systems
1. **Zammad** — helpdesk tickets, customer profiles, queue stats, agent workloads
2. **Billing (MetaBase)** — client financials: invoices, payments, outstanding balances, services, annuities
3. **XWiki** — internal documentation, client notes, technical procedures
4. **Escalate** — flag for senior support when you can't answer

## CRITICAL: Cross-Reference ALL Systems
When asked about a person or customer, **ALWAYS query ALL relevant systems**, not just one:
- **Customer lookup** → search Zammad (customer profile + tickets) AND billing (client financials + services) AND XWiki (documentation/notes)
- **Ticket inquiry** → get ticket details AND look up the customer in billing for account context
- **General questions** → search XWiki for docs AND Zammad for related tickets

DO NOT stop after querying one system. The user expects a COMPREHENSIVE answer combining data from every source.

## How to Answer Well
1. **Use multiple tools per question** — a customer lookup should trigger 3+ tool calls (Zammad customer, billing client, XWiki search)
2. **Be thorough** — include all relevant details: contact info, address, account numbers, ticket history, financial status, service details
3. **Format with markdown** — use tables for lists, bold for key info, sections with headers for different data sources
4. **Structure your answer by source** — e.g. "### Contact Details (Zammad)" then "### Billing & Services" then "### Ticket History" then "### Documentation"
5. **Ticket numbers** — always show the display number (7+ digits) and link: https://z.ictglobe.support/#ticket/zoom/{internal_id}
6. **Money** — billing amounts are in Rands (ZAR). Show outstanding balances prominently.
7. **Summarize ticket articles** — don't just list tickets, summarize what the conversations were about

## When to Escalate
- You genuinely cannot find the information after searching all systems
- The user needs an action performed (update ticket, change account, etc.)
- The question requires judgment beyond your data
- You're unsure about something important

## Rules
- You CANNOT modify any data — read only
- Report information from tools accurately — never fabricate data or URLs
- If a tool returns no results, mention that you searched but found nothing (don't silently skip it)
- If a search fails, try alternative search terms
- Be professional but friendly — South African warm, not corporate cold`;

const SHERPA_TOOLS = [
  { type: 'function', function: { name: 'zammad_search', description: 'Search Zammad tickets by keyword. Use for finding tickets by customer name, subject, content, etc.', parameters: { type: 'object', properties: { query: { type: 'string', description: 'Search query — can be customer name, keyword, ticket number, etc.' } }, required: ['query'] } } },
  { type: 'function', function: { name: 'zammad_ticket', description: 'Get full details of a specific ticket including all articles/messages. Accepts ticket number (e.g. 43274489) or internal ID.', parameters: { type: 'object', properties: { id: { type: 'string', description: 'Ticket number or internal ID' } }, required: ['id'] } } },
  { type: 'function', function: { name: 'zammad_customer', description: 'Look up a customer by name, email, or phone. Returns customer profile and their tickets.', parameters: { type: 'object', properties: { query: { type: 'string', description: 'Customer name, email, or phone number' } }, required: ['query'] } } },
  { type: 'function', function: { name: 'zammad_stats', description: 'Get ticket queue statistics — counts by state (new, open, pending, etc.)', parameters: { type: 'object', properties: {} } } },
  { type: 'function', function: { name: 'zammad_agents', description: 'List all support agents with their ticket counts broken down by state. Shows workload distribution.', parameters: { type: 'object', properties: {} } } },
  { type: 'function', function: { name: 'zammad_aging', description: 'Ticket age report: age distribution buckets, oldest tickets, stalest (least recently updated) tickets, average age by state.', parameters: { type: 'object', properties: { top: { type: 'string', description: 'Number of oldest/stalest to show (default 10)' } } } } },
  { type: 'function', function: { name: 'xwiki_search', description: 'Search the MoreNET documentation wiki for procedures, guides, and knowledge base articles.', parameters: { type: 'object', properties: { query: { type: 'string', description: 'Search query' } }, required: ['query'] } } },
  { type: 'function', function: { name: 'xwiki_get', description: 'Get full content of a specific wiki page by its ID.', parameters: { type: 'object', properties: { id: { type: 'string', description: 'Page ID' } }, required: ['id'] } } },
  { type: 'function', function: { name: 'billing_client', description: 'Get client financial overview from billing system: account details, invoices, outstanding balance, payment history. Search by name, company, or account number.', parameters: { type: 'object', properties: { name: { type: 'string', description: 'Client name, company name, or account number' } }, required: ['name'] } } },
  { type: 'function', function: { name: 'billing_invoices', description: 'Get invoice history for a client. Shows recent invoices with amounts, dates, and outstanding balances.', parameters: { type: 'object', properties: { name: { type: 'string', description: 'Client name or company' }, months: { type: 'string', description: 'Number of months to look back (default 6)' } }, required: ['name'] } } },
  { type: 'function', function: { name: 'billing_annuity', description: 'Get recurring billing (MRC/monthly services) for a client. Shows active subscriptions and monthly charges.', parameters: { type: 'object', properties: { name: { type: 'string', description: 'Client name or company' } }, required: ['name'] } } },
  { type: 'function', function: { name: 'billing_search', description: 'Search billing system for clients by name, company, or account number. Use for finding the right client when you have partial info.', parameters: { type: 'object', properties: { query: { type: 'string', description: 'Search query' } }, required: ['query'] } } },
  { type: 'function', function: { name: 'escalate', description: 'Escalate a question or request to the senior NEX orchestrator for help. Use when you cannot answer, need an action performed, or need human judgment.', parameters: { type: 'object', properties: { reason: { type: 'string', description: 'What the user needs and why you are escalating' }, context: { type: 'string', description: 'Relevant context: ticket numbers, customer info, what you already tried' } }, required: ['reason'] } } },
];

const TOOL_COMMANDS = {
  zammad_search: (args) => ['python3', path.join(__dirname, 'zammad.py'), 'search', args.query || ''],
  zammad_ticket: (args) => ['python3', path.join(__dirname, 'zammad.py'), 'ticket', String(args.id || '')],
  zammad_customer: (args) => ['python3', path.join(__dirname, 'zammad.py'), 'customer', args.query || ''],
  zammad_stats: () => ['python3', path.join(__dirname, 'zammad.py'), 'stats'],
  zammad_agents: () => ['python3', path.join(__dirname, 'zammad.py'), 'agents'],
  zammad_aging: (args) => ['python3', path.join(__dirname, 'zammad.py'), 'aging', '--top', String(args.top || '10')],
  xwiki_search: (args) => ['python3', path.join(__dirname, 'xwiki.py'), 'search', args.query || ''],
  xwiki_get: (args) => ['python3', path.join(__dirname, 'xwiki.py'), 'get', String(args.id || '')],
  billing_client: (args) => ['python3', path.join(__dirname, 'metabase.py'), 'client', args.name || ''],
  billing_invoices: (args) => {
    const cmd = ['python3', path.join(__dirname, 'metabase.py'), 'invoices', args.name || ''];
    if (args.months) cmd.push('--months', String(args.months));
    return cmd;
  },
  billing_annuity: (args) => ['python3', path.join(__dirname, 'metabase.py'), 'annuity', args.name || ''],
  billing_search: (args) => ['python3', path.join(__dirname, 'metabase.py'), 'search', args.query || ''],
};

function executeTool(name, args) {
  // Handle escalation specially
  if (name === 'escalate') {
    return handleEscalation(args);
  }
  const cmdBuilder = TOOL_COMMANDS[name];
  if (!cmdBuilder) return `Unknown tool: ${name}`;
  const [cmd, ...cmdArgs] = cmdBuilder(args);
  try {
    const result = execFileSync(cmd, cmdArgs, {
      timeout: 30000,
      maxBuffer: 1024 * 1024,
      encoding: 'utf8',
      env: { ...process.env, PATH: process.env.PATH },
    });
    return result.substring(0, 12000); // increased cap
  } catch (err) {
    return `Tool error: ${err.message || 'execution failed'}`;
  }
}

// ── Escalation Handler ──────────────────────────────────
function handleEscalation(args) {
  const escalation = {
    id: crypto.randomBytes(8).toString('hex'),
    timestamp: new Date().toISOString(),
    reason: args.reason || 'Unknown',
    context: args.context || '',
    status: 'pending',
  };

  // Save to escalations log
  const escFile = path.join(path.dirname(DATA_FILE), 'escalations.json');
  let escalations = [];
  try { escalations = JSON.parse(fs.readFileSync(escFile, 'utf8')); } catch {}
  escalations.push(escalation);
  // Keep last 500 escalations
  if (escalations.length > 500) escalations = escalations.slice(-500);
  fs.writeFileSync(escFile, JSON.stringify(escalations, null, 2));

  // Send Telegram notification to admin
  if (TELEGRAM_BOT_TOKEN && TELEGRAM_ADMIN_CHAT_ID) {
    const text = `🔔 *Sherpa Escalation*\n\n*Reason:* ${escalation.reason}\n*Context:* ${escalation.context || 'None'}\n*Time:* ${escalation.timestamp}\n*ID:* \`${escalation.id}\``;
    fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: TELEGRAM_ADMIN_CHAT_ID,
        text,
        parse_mode: 'Markdown',
      }),
    }).catch(err => console.error('Telegram escalation failed:', err.message));
  }

  console.log(`ESCALATION [${escalation.id}]: ${escalation.reason}`);
  return `Escalation logged (ID: ${escalation.id}). The senior support team has been notified and will follow up.`;
}

// ── Chat Persistence ────────────────────────────────────
const CHATS_DIR = path.join(path.dirname(DATA_FILE), 'chats');
if (!fs.existsSync(CHATS_DIR)) fs.mkdirSync(CHATS_DIR, { recursive: true });

function getChatFile(userId) {
  // One file per user per day
  const date = new Date().toISOString().slice(0, 10);
  const safeUser = userId.replace(/[^a-zA-Z0-9@._-]/g, '_');
  return path.join(CHATS_DIR, `${safeUser}_${date}.json`);
}

function loadChat(userId) {
  const file = getChatFile(userId);
  try {
    if (fs.existsSync(file)) {
      return JSON.parse(fs.readFileSync(file, 'utf8'));
    }
  } catch {}
  return { userId, date: new Date().toISOString().slice(0, 10), messages: [] };
}

function saveChat(chatData) {
  const file = getChatFile(chatData.userId);
  fs.writeFileSync(file, JSON.stringify(chatData, null, 2));
}

function listChats(limit = 50) {
  try {
    const files = fs.readdirSync(CHATS_DIR)
      .filter(f => f.endsWith('.json'))
      .sort()
      .reverse()
      .slice(0, limit);
    return files.map(f => {
      try {
        const data = JSON.parse(fs.readFileSync(path.join(CHATS_DIR, f), 'utf8'));
        return {
          file: f,
          userId: data.userId,
          date: data.date,
          messageCount: data.messages.length,
          lastMessage: data.messages.length > 0 ? data.messages[data.messages.length - 1].timestamp : null,
        };
      } catch { return { file: f, error: true }; }
    });
  } catch { return []; }
}

function getChatDetail(filename) {
  try {
    return JSON.parse(fs.readFileSync(path.join(CHATS_DIR, filename), 'utf8'));
  } catch { return null; }
}

async function callLLM(messages, tools) {
  const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
    },
    body: JSON.stringify({ model: SHERPA_MODEL, messages, tools, max_tokens: 4096 }),
  });
  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`LLM API error ${res.status}: ${errText}`);
  }
  return res.json();
}

// In-memory conversation context (for LLM multi-turn)
const chatContext = new Map();
const MAX_CONTEXT = 30;

app.post('/api/chat', apiAuthMiddleware, async (req, res) => {
  if (!OPENROUTER_API_KEY) {
    return res.status(503).json({ error: 'Chat not configured (missing API key)' });
  }

  const { message } = req.body;
  if (!message || typeof message !== 'string' || message.length > 4000) {
    return res.status(400).json({ error: 'Message required (max 4000 chars)' });
  }

  // Handle reset command
  if (message === '/reset') {
    chatContext.delete(req.user.email);
    return res.json({ reply: 'Conversation reset.' });
  }

  const userId = req.user.email;
  const userName = req.user.name || userId;

  // Load/init context
  if (!chatContext.has(userId)) chatContext.set(userId, []);
  const context = chatContext.get(userId);

  context.push({ role: 'user', content: message });
  if (context.length > MAX_CONTEXT) context.splice(0, context.length - MAX_CONTEXT);

  // Persist user message
  const chatData = loadChat(userId);
  chatData.messages.push({
    role: 'user',
    content: message,
    timestamp: new Date().toISOString(),
    userName,
  });

  const messages = [
    { role: 'system', content: SHERPA_SYSTEM },
    ...context,
  ];

  try {
    let attempts = 0;
    const MAX_TOOL_ROUNDS = 8;

    while (attempts < MAX_TOOL_ROUNDS) {
      const data = await callLLM(messages, SHERPA_TOOLS);
      const choice = data.choices?.[0];
      if (!choice) throw new Error('No response from LLM');

      const msg = choice.message;

      // If there are tool calls, execute them and loop
      if (msg.tool_calls && msg.tool_calls.length > 0) {
        messages.push(msg);
        for (const tc of msg.tool_calls) {
          let args = {};
          try { args = JSON.parse(tc.function.arguments || '{}'); } catch {}
          console.log(`Sherpa tool: ${tc.function.name}(${JSON.stringify(args)}) [user: ${userId}]`);

          // Add user context to escalations
          if (tc.function.name === 'escalate') {
            args._user = userId;
            args._userName = userName;
          }

          const result = executeTool(tc.function.name, args);
          messages.push({ role: 'tool', tool_call_id: tc.id, content: result });

          // Log tool calls to chat history
          chatData.messages.push({
            role: 'tool',
            tool: tc.function.name,
            args,
            result: result.substring(0, 2000),
            timestamp: new Date().toISOString(),
          });
        }
        attempts++;
        continue;
      }

      // Final text response
      const reply = msg.content || 'I couldn\'t generate a response.';
      context.push({ role: 'assistant', content: reply });
      if (context.length > MAX_CONTEXT) context.splice(0, context.length - MAX_CONTEXT);

      // Persist assistant response
      chatData.messages.push({
        role: 'assistant',
        content: reply,
        timestamp: new Date().toISOString(),
        model: SHERPA_MODEL,
      });
      saveChat(chatData);

      return res.json({ reply });
    }

    const fallback = 'I hit my tool usage limit for this question. Try rephrasing or I can escalate this for you.';
    chatData.messages.push({ role: 'assistant', content: fallback, timestamp: new Date().toISOString() });
    saveChat(chatData);
    return res.json({ reply: fallback });
  } catch (err) {
    console.error('Sherpa error:', err.message);
    chatData.messages.push({ role: 'error', content: err.message, timestamp: new Date().toISOString() });
    saveChat(chatData);
    return res.status(500).json({ error: 'Sherpa encountered an error. Please try again.' });
  }
});

// ── Admin: Chat History API ─────────────────────────────
app.get('/api/admin/chats', apiAuthMiddleware, adminMiddleware, (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  res.json(listChats(limit));
});

app.get('/api/admin/chats/:filename', apiAuthMiddleware, adminMiddleware, (req, res) => {
  const filename = req.params.filename.replace(/[^a-zA-Z0-9@._-]/g, '');
  const data = getChatDetail(filename + '.json');
  if (!data) return res.status(404).json({ error: 'Chat not found' });
  res.json(data);
});

// ── Admin: Escalations API ──────────────────────────────
app.get('/api/admin/escalations', apiAuthMiddleware, adminMiddleware, (req, res) => {
  const escFile = path.join(path.dirname(DATA_FILE), 'escalations.json');
  try {
    const data = JSON.parse(fs.readFileSync(escFile, 'utf8'));
    res.json(data.reverse());
  } catch { res.json([]); }
});

// ── Protected App ────────────────────────────────────────
app.get('/', authMiddleware, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/me', apiAuthMiddleware, (req, res) => {
  res.json(req.user);
});

app.use(authMiddleware, express.static(path.join(__dirname, 'public')));

// ── Start ────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`NEX Portal running on port ${PORT} [auth: ${OIDC_ENABLED ? 'Authentik OIDC' : 'local'}]`);
});
