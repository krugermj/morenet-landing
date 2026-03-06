const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

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
