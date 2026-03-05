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

// Initialize with admin user if empty
let users = loadUsers();
if (!users.find(u => u.email === ADMIN_EMAIL)) {
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
  console.log(`Admin user created: ${ADMIN_EMAIL}`);
}

// ── Middleware ────────────────────────────────────────────
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
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const user = users.find(u => u.email === email.toLowerCase().trim());
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

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

// ── Admin Routes ─────────────────────────────────────────
app.get('/api/users', authMiddleware, adminMiddleware, (req, res) => {
  const safeUsers = users.map(u => ({
    id: u.id, email: u.email, name: u.name, role: u.role,
    created_at: u.created_at, last_login: u.last_login
  }));
  res.json(safeUsers);
});

app.post('/api/users', authMiddleware, adminMiddleware, (req, res) => {
  const { email, password, name, role } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

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
  res.json({ success: true, id: newUser.id });
});

app.delete('/api/users/:id', authMiddleware, adminMiddleware, (req, res) => {
  const userId = parseInt(req.params.id);
  if (userId === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
  users = users.filter(u => u.id !== userId);
  saveUsers(users);
  res.json({ success: true });
});

// ── Protected App ────────────────────────────────────────
app.get('/', authMiddleware, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/me', authMiddleware, (req, res) => {
  res.json(req.user);
});

app.use(authMiddleware, express.static(path.join(__dirname, 'public')));

// ── Start ────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`NEX Portal running on port ${PORT}`);
});
