const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@morenet.co.za';
const ADMIN_PASS = process.env.ADMIN_PASS || 'changeme';

// ── Database ─────────────────────────────────────────────
const db = new Database('/data/nex.db');
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT,
    role TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME
  )
`);

// Seed admin if not exists
const adminExists = db.prepare('SELECT id FROM users WHERE email = ?').get(ADMIN_EMAIL);
if (!adminExists) {
  const hash = bcrypt.hashSync(ADMIN_PASS, 10);
  db.prepare('INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)').run(ADMIN_EMAIL, hash, 'Admin', 'admin');
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

// ── Auth Routes ──────────────────────────────────────────
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim());
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);

  const token = jwt.sign(
    { id: user.id, email: user.email, name: user.name, role: user.role },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.cookie('nex_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  });

  res.json({ success: true, name: user.name, role: user.role });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('nex_token');
  res.json({ success: true });
});

// ── Admin Routes ─────────────────────────────────────────
app.get('/api/users', authMiddleware, adminMiddleware, (req, res) => {
  const users = db.prepare('SELECT id, email, name, role, created_at, last_login FROM users ORDER BY created_at').all();
  res.json(users);
});

app.post('/api/users', authMiddleware, adminMiddleware, (req, res) => {
  const { email, password, name, role } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  try {
    const hash = bcrypt.hashSync(password, 10);
    const result = db.prepare('INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)').run(
      email.toLowerCase().trim(), hash, name || '', role || 'user'
    );
    res.json({ success: true, id: result.lastInsertRowid });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(409).json({ error: 'Email already exists' });
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/users/:id', authMiddleware, adminMiddleware, (req, res) => {
  const userId = parseInt(req.params.id);
  if (userId === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
  db.prepare('DELETE FROM users WHERE id = ?').run(userId);
  res.json({ success: true });
});

app.put('/api/users/:id/password', authMiddleware, adminMiddleware, (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required' });
  const hash = bcrypt.hashSync(password, 10);
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, parseInt(req.params.id));
  res.json({ success: true });
});

// ── Public assets for login page ─────────────────────────
app.get('/login/logo.png', (req, res) => res.sendFile(path.join(__dirname, 'public', 'logo.png')));
app.get('/login/nex.png', (req, res) => res.sendFile(path.join(__dirname, 'public', 'nex.png')));

// ── Protected App ────────────────────────────────────────
app.get('/', authMiddleware, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/me', authMiddleware, (req, res) => {
  res.json(req.user);
});

// Static files (logo, nex avatar) — protected
app.use(authMiddleware, express.static(path.join(__dirname, 'public')));

// ── Start ────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`NEX Portal running on port ${PORT}`);
});
