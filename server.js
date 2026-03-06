const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@morenet.co.za';
const ADMIN_PASS = process.env.ADMIN_PASS || 'changeme';

// ── Simple JSON-based user store ─────────────────────────
const DATA_FILE = process.env.DATA_FILE || '/app/data/users.json';

function loadUsers() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    }
  } catch (e) {
    console.error('Error loading users:', e.message);
  }
  return [];
}

function saveUsers(users) {
  const dir = path.dirname(DATA_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(DATA_FILE, JSON.stringify(users, null, 2));
}

// Initialize with admin user ONLY if no users exist at all
let users = loadUsers();
if (users.length === 0) {
  users.push({
    id: 1,
    email: ADMIN_EMAIL,
    password: bcrypt.hashSync(ADMIN_PASS, 10),
    name: 'Admin',
    role: 'admin',
    created_at: new Date().toISOString(),
    last_login: null
  });
  saveUsers(users);
  console.log(`Initial admin user created: ${ADMIN_EMAIL}`);
} else {
  console.log(`Loaded ${users.length} existing users from store.`);
}

// ── Rate Limiter ─────────────────────────────────────────
const loginAttempts = new Map(); // ip -> { count, firstAttempt, lockedUntil }
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const MAX_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minute lockout

function rateLimitCheck(ip) {
  const now = Date.now();
  const record = loginAttempts.get(ip);

  if (!record) return { allowed: true };

  // If locked out, check if lockout expired
  if (record.lockedUntil && now < record.lockedUntil) {
    const remaining = Math.ceil((record.lockedUntil - now) / 1000 / 60);
    return { allowed: false, remaining };
  }

  // If window expired, reset
  if (now - record.firstAttempt > RATE_LIMIT_WINDOW) {
    loginAttempts.delete(ip);
    return { allowed: true };
  }

  if (record.count >= MAX_ATTEMPTS) {
    record.lockedUntil = now + LOCKOUT_DURATION;
    const remaining = Math.ceil(LOCKOUT_DURATION / 1000 / 60);
    return { allowed: false, remaining };
  }

  return { allowed: true };
}

function rateLimitRecord(ip) {
  const now = Date.now();
  const record = loginAttempts.get(ip) || { count: 0, firstAttempt: now };
  record.count++;
  loginAttempts.set(ip, record);
}

function rateLimitReset(ip) {
  loginAttempts.delete(ip);
}

// Clean up stale entries every 30 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of loginAttempts) {
    if (now - record.firstAttempt > RATE_LIMIT_WINDOW * 2) {
      loginAttempts.delete(ip);
    }
  }
}, 30 * 60 * 1000);

// ── Middleware ────────────────────────────────────────────
app.set('trust proxy', true); // trust Traefik/Coolify proxy for real IP
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

function authMiddleware(req, res, next) {
  const token = req.cookies.nex_token;
  if (!token) return res.redirect('/login');
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
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
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
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

// ── Health Check ─────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', port: PORT }));

// ── Public assets for login page ─────────────────────────
app.get('/login/logo.png', (req, res) => res.sendFile(path.join(__dirname, 'public', 'logo.png')));
app.get('/login/nex.png', (req, res) => res.sendFile(path.join(__dirname, 'public', 'nex.png')));

// ── Auth Routes ──────────────────────────────────────────
app.get('/login', (req, res) => {
  // If already logged in, redirect to home
  const token = req.cookies.nex_token;
  if (token) {
    try {
      jwt.verify(token, JWT_SECRET);
      return res.redirect('/');
    } catch {}
  }
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.post('/api/login', (req, res) => {
  const ip = req.ip;

  // Rate limit check
  const rateCheck = rateLimitCheck(ip);
  if (!rateCheck.allowed) {
    return res.status(429).json({
      error: `Too many login attempts. Try again in ${rateCheck.remaining} minute${rateCheck.remaining > 1 ? 's' : ''}.`
    });
  }

  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  // Reload users from disk (in case another instance changed it)
  users = loadUsers();

  const user = users.find(u => u.email === email.toLowerCase().trim());
  if (!user || !bcrypt.compareSync(password, user.password)) {
    rateLimitRecord(ip);
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Successful login — reset rate limit
  rateLimitReset(ip);

  user.last_login = new Date().toISOString();
  saveUsers(users);

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

  res.json({ success: true, name: user.name, role: user.role });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('nex_token');
  res.json({ success: true });
});

// ── User Self-Service Routes ─────────────────────────────
app.post('/api/change-password', apiAuthMiddleware, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current and new password required' });
  }
  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters' });
  }

  users = loadUsers();
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (!bcrypt.compareSync(currentPassword, user.password)) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }

  user.password = bcrypt.hashSync(newPassword, 10);
  saveUsers(users);

  res.json({ success: true, message: 'Password updated successfully' });
});

// ── Admin Routes ─────────────────────────────────────────
app.get('/admin', authMiddleware, adminMiddleware, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});

// Serve assets for admin page
app.get('/admin/logo.png', (req, res) => res.sendFile(path.join(__dirname, 'public', 'logo.png')));
app.get('/admin/nex.png', (req, res) => res.sendFile(path.join(__dirname, 'public', 'nex.png')));

app.get('/api/users', apiAuthMiddleware, adminMiddleware, (req, res) => {
  users = loadUsers();
  const safeUsers = users.map(u => ({
    id: u.id, email: u.email, name: u.name, role: u.role,
    created_at: u.created_at, last_login: u.last_login
  }));
  res.json(safeUsers);
});

app.post('/api/users', apiAuthMiddleware, adminMiddleware, (req, res) => {
  const { email, password, name, role } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

  users = loadUsers();
  if (users.find(u => u.email === email.toLowerCase().trim())) {
    return res.status(409).json({ error: 'Email already exists' });
  }

  const newUser = {
    id: Math.max(...users.map(u => u.id), 0) + 1,
    email: email.toLowerCase().trim(),
    password: bcrypt.hashSync(password, 10),
    name: name || '',
    role: role || 'user',
    created_at: new Date().toISOString(),
    last_login: null
  };
  users.push(newUser);
  saveUsers(users);
  res.json({ success: true, id: newUser.id, email: newUser.email });
});

app.put('/api/users/:id', apiAuthMiddleware, adminMiddleware, (req, res) => {
  const userId = parseInt(req.params.id);
  users = loadUsers();
  const user = users.find(u => u.id === userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const { name, email, role, password } = req.body;
  if (name !== undefined) user.name = name;
  if (email !== undefined) user.email = email.toLowerCase().trim();
  if (role !== undefined) {
    // Prevent demoting yourself
    if (userId === req.user.id && role !== 'admin') {
      return res.status(400).json({ error: 'Cannot remove your own admin role' });
    }
    user.role = role;
  }
  if (password) {
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    user.password = bcrypt.hashSync(password, 10);
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
  console.log(`NEX Portal running on port ${PORT}`);
});
