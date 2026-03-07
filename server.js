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
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';
const SHERPA_MODEL = process.env.SHERPA_MODEL || 'gemini-2.0-flash';
const SHERPA_SYSTEM = `You are Sherpa, a read-only helpdesk assistant for MoreNET service desk agents. You help look up tickets, customers, and documentation. You have tools for Zammad (helpdesk) and XWiki (documentation). Be concise and helpful. You CANNOT modify any data - read only. Format responses with markdown when helpful.`;

const SHERPA_TOOLS = [
  { type: 'function', function: { name: 'zammad_search', description: 'Search Zammad tickets by keyword', parameters: { type: 'object', properties: { query: { type: 'string', description: 'Search query' } }, required: ['query'] } } },
  { type: 'function', function: { name: 'zammad_ticket', description: 'Get a specific Zammad ticket by ID', parameters: { type: 'object', properties: { id: { type: 'string', description: 'Ticket ID number' } }, required: ['id'] } } },
  { type: 'function', function: { name: 'zammad_customer', description: 'Look up a Zammad customer by name or email', parameters: { type: 'object', properties: { query: { type: 'string', description: 'Customer name or email' } }, required: ['query'] } } },
  { type: 'function', function: { name: 'zammad_stats', description: 'Get Zammad ticket statistics overview', parameters: { type: 'object', properties: {} } } },
  { type: 'function', function: { name: 'xwiki_search', description: 'Search XWiki documentation', parameters: { type: 'object', properties: { query: { type: 'string', description: 'Search query' } }, required: ['query'] } } },
  { type: 'function', function: { name: 'xwiki_get', description: 'Get a specific XWiki page by ID', parameters: { type: 'object', properties: { id: { type: 'string', description: 'Page ID' } }, required: ['id'] } } },
];

const TOOL_COMMANDS = {
  zammad_search: (args) => ['python3', path.join(__dirname, 'zammad.py'), 'search', args.query || ''],
  zammad_ticket: (args) => ['python3', path.join(__dirname, 'zammad.py'), 'ticket', String(args.id || '')],
  zammad_customer: (args) => ['python3', path.join(__dirname, 'zammad.py'), 'customer', args.query || ''],
  zammad_stats: () => ['python3', path.join(__dirname, 'zammad.py'), 'stats'],
  xwiki_search: (args) => ['python3', path.join(__dirname, 'xwiki.py'), 'search', args.query || ''],
  xwiki_get: (args) => ['python3', path.join(__dirname, 'xwiki.py'), 'get', String(args.id || '')],
};

function executeTool(name, args) {
  const cmdBuilder = TOOL_COMMANDS[name];
  if (!cmdBuilder) return `Unknown tool: ${name}`;
  const [cmd, ...cmdArgs] = cmdBuilder(args);
  try {
    const result = execFileSync(cmd, cmdArgs, {
      timeout: 15000,
      maxBuffer: 512 * 1024,
      encoding: 'utf8',
      env: { ...process.env, PATH: process.env.PATH },
    });
    return result.substring(0, 8000); // cap output
  } catch (err) {
    return `Tool error: ${err.message || 'execution failed'}`;
  }
}

// Convert OpenAI-style messages to Gemini format
function toGeminiContents(messages) {
  const contents = [];
  for (const m of messages) {
    if (m.role === 'system') continue; // handled separately
    if (m.role === 'user') {
      contents.push({ role: 'user', parts: [{ text: m.content }] });
    } else if (m.role === 'assistant') {
      if (m.tool_calls) {
        const parts = m.tool_calls.map(tc => ({
          functionCall: { name: tc.function.name, args: JSON.parse(tc.function.arguments || '{}') }
        }));
        if (m.content) parts.unshift({ text: m.content });
        contents.push({ role: 'model', parts });
      } else {
        contents.push({ role: 'model', parts: [{ text: m.content || '' }] });
      }
    } else if (m.role === 'tool') {
      contents.push({ role: 'user', parts: [{ functionResponse: { name: m._toolName || 'tool', response: { result: m.content } } }] });
    }
  }
  return contents;
}

function toGeminiTools(tools) {
  return [{ functionDeclarations: tools.map(t => ({
    name: t.function.name,
    description: t.function.description,
    parameters: t.function.parameters,
  })) }];
}

async function callLLM(messages, tools) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${SHERPA_MODEL}:generateContent?key=${GEMINI_API_KEY}`;
  const systemMsg = messages.find(m => m.role === 'system');
  const body = {
    contents: toGeminiContents(messages),
    tools: toGeminiTools(tools),
    systemInstruction: systemMsg ? { parts: [{ text: systemMsg.content }] } : undefined,
    generationConfig: { maxOutputTokens: 2048 },
  };

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Gemini API error ${res.status}: ${errText}`);
  }
  const data = await res.json();

  // Convert Gemini response to OpenAI-compatible format
  const candidate = data.candidates?.[0];
  if (!candidate) throw new Error('No response from Gemini');

  const parts = candidate.content?.parts || [];
  const textParts = parts.filter(p => p.text).map(p => p.text).join('');
  const funcCalls = parts.filter(p => p.functionCall);

  if (funcCalls.length > 0) {
    return { choices: [{ message: {
      role: 'assistant',
      content: textParts || null,
      tool_calls: funcCalls.map((fc, i) => ({
        id: `call_${i}`,
        type: 'function',
        function: { name: fc.functionCall.name, arguments: JSON.stringify(fc.functionCall.args || {}) }
      }))
    }}]};
  }

  return { choices: [{ message: { role: 'assistant', content: textParts || 'No response.' } }] };
}

// Per-user conversation history (in-memory, last 20 messages)
const chatHistory = new Map();
const MAX_HISTORY = 20;

app.post('/api/chat', apiAuthMiddleware, async (req, res) => {
  if (!GEMINI_API_KEY) {
    return res.status(503).json({ error: 'Chat not configured (missing Gemini API key)' });
  }

  const { message } = req.body;
  if (!message || typeof message !== 'string' || message.length > 2000) {
    return res.status(400).json({ error: 'Message required (max 2000 chars)' });
  }

  const userId = req.user.email;
  if (!chatHistory.has(userId)) chatHistory.set(userId, []);
  const history = chatHistory.get(userId);

  history.push({ role: 'user', content: message });
  if (history.length > MAX_HISTORY) history.splice(0, history.length - MAX_HISTORY);

  const messages = [
    { role: 'system', content: SHERPA_SYSTEM },
    ...history,
  ];

  try {
    let attempts = 0;
    const MAX_TOOL_ROUNDS = 5;

    while (attempts < MAX_TOOL_ROUNDS) {
      const data = await callLLM(messages, SHERPA_TOOLS);
      const choice = data.choices?.[0];
      if (!choice) throw new Error('No response from LLM');

      const msg = choice.message;

      // If there are tool calls, execute them and loop
      if (msg.tool_calls && msg.tool_calls.length > 0) {
        messages.push(msg); // add assistant message with tool_calls
        for (const tc of msg.tool_calls) {
          let args = {};
          try { args = JSON.parse(tc.function.arguments || '{}'); } catch {}
          console.log(`Sherpa tool: ${tc.function.name}(${JSON.stringify(args)}) [user: ${userId}]`);
          const result = executeTool(tc.function.name, args);
          messages.push({ role: 'tool', tool_call_id: tc.id, content: result, _toolName: tc.function.name });
        }
        attempts++;
        continue;
      }

      // Final text response
      const reply = msg.content || 'I couldn\'t generate a response.';
      history.push({ role: 'assistant', content: reply });
      if (history.length > MAX_HISTORY) history.splice(0, history.length - MAX_HISTORY);
      return res.json({ reply });
    }

    return res.json({ reply: 'I hit my tool usage limit for this question. Try rephrasing?' });
  } catch (err) {
    console.error('Sherpa error:', err.message);
    return res.status(500).json({ error: 'Sherpa encountered an error. Please try again.' });
  }
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
