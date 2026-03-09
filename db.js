/**
 * PostgreSQL storage layer for NEX Portal.
 * Replaces JSON file storage for users, chats, and escalations.
 */
const { Pool } = require('pg');

const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://nex:nex_secret_2026@qs88cwws0s00g804sok00ggs:5432/nex_portal';

const pool = new Pool({
  connectionString: DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => {
  console.error('Unexpected PG pool error:', err.message);
});

// ── Schema ───────────────────────────────────────────────

async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password TEXT,
        name TEXT DEFAULT '',
        role TEXT DEFAULT 'user',
        auth TEXT DEFAULT 'local',
        groups JSONB DEFAULT '[]',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        last_login TIMESTAMPTZ
      );

      CREATE TABLE IF NOT EXISTS chat_messages (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        user_name TEXT DEFAULT '',
        chat_date DATE DEFAULT CURRENT_DATE,
        role TEXT NOT NULL,
        content TEXT,
        tool_name TEXT,
        tool_args JSONB,
        tool_result TEXT,
        model TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_chat_user_date ON chat_messages(user_email, chat_date);

      CREATE TABLE IF NOT EXISTS escalations (
        id TEXT PRIMARY KEY,
        reason TEXT,
        context TEXT,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS chat_meta (
        chat_key TEXT PRIMARY KEY,
        reviewed BOOLEAN DEFAULT FALSE,
        reviewed_by TEXT,
        reviewed_at TIMESTAMPTZ
      );
    `);
    console.log('Database tables initialized.');
  } finally {
    client.release();
  }
}

// ── Users ────────────────────────────────────────────────

async function loadUsers() {
  const { rows } = await pool.query(
    'SELECT id, email, password, name, role, auth, groups, created_at, last_login FROM users ORDER BY id'
  );
  return rows.map(r => ({
    ...r,
    groups: r.groups || [],
    created_at: r.created_at?.toISOString(),
    last_login: r.last_login?.toISOString() || null,
  }));
}

async function findUserByEmail(email) {
  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase().trim()]);
  if (rows.length === 0) return null;
  const r = rows[0];
  return { ...r, groups: r.groups || [], created_at: r.created_at?.toISOString(), last_login: r.last_login?.toISOString() || null };
}

async function upsertUser({ email, name, role, auth, password, groups }) {
  email = email.toLowerCase().trim();
  const existing = await findUserByEmail(email);
  if (existing) {
    const { rows } = await pool.query(
      `UPDATE users SET name = COALESCE($2, name), role = COALESCE($3, role), auth = COALESCE($4, auth),
       groups = COALESCE($5, groups), last_login = NOW()
       WHERE email = $1 RETURNING *`,
      [email, name || null, role || null, auth || null, groups ? JSON.stringify(groups) : null]
    );
    const r = rows[0];
    return { ...r, groups: r.groups || [], created_at: r.created_at?.toISOString(), last_login: r.last_login?.toISOString() };
  } else {
    const { rows } = await pool.query(
      `INSERT INTO users (email, name, role, auth, password, groups, last_login)
       VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING *`,
      [email, name || '', role || 'user', auth || 'local', password || null, JSON.stringify(groups || [])]
    );
    const r = rows[0];
    return { ...r, groups: r.groups || [], created_at: r.created_at?.toISOString(), last_login: r.last_login?.toISOString() };
  }
}

async function updateUser(id, { name, role }) {
  const sets = [];
  const vals = [];
  let i = 1;
  if (name !== undefined) { sets.push(`name = $${i++}`); vals.push(name); }
  if (role !== undefined) { sets.push(`role = $${i++}`); vals.push(role); }
  if (sets.length === 0) return null;
  vals.push(id);
  const { rows } = await pool.query(`UPDATE users SET ${sets.join(', ')} WHERE id = $${i} RETURNING *`, vals);
  return rows[0] || null;
}

async function deleteUser(id) {
  await pool.query('DELETE FROM users WHERE id = $1', [id]);
}

// ── Chats ────────────────────────────────────────────────

async function saveChatMessage({ userEmail, userName, role, content, toolName, toolArgs, toolResult, model }) {
  await pool.query(
    `INSERT INTO chat_messages (user_email, user_name, chat_date, role, content, tool_name, tool_args, tool_result, model)
     VALUES ($1, $2, CURRENT_DATE, $3, $4, $5, $6, $7, $8)`,
    [userEmail, userName || '', role, content || null, toolName || null,
     toolArgs ? JSON.stringify(toolArgs) : null, toolResult ? toolResult.substring(0, 4000) : null, model || null]
  );
}

async function listChats(limit = 50, showReviewed = false) {
  let query = `
    SELECT user_email, chat_date, COUNT(*) as message_count,
           MAX(created_at) as last_message
    FROM chat_messages
    GROUP BY user_email, chat_date
    ORDER BY last_message DESC
    LIMIT $1
  `;
  const { rows } = await pool.query(query, [limit]);

  const results = [];
  for (const r of rows) {
    const chatKey = `${r.user_email}_${r.chat_date.toISOString().slice(0, 10)}`;
    const meta = await getChatMeta(chatKey);
    if (!showReviewed && meta?.reviewed) continue;
    results.push({
      file: chatKey,
      userId: r.user_email,
      date: r.chat_date.toISOString().slice(0, 10),
      messageCount: parseInt(r.message_count),
      lastMessage: r.last_message?.toISOString(),
      reviewed: meta?.reviewed || false,
      reviewedBy: meta?.reviewed_by || null,
    });
  }
  return results;
}

async function getChatDetail(chatKey) {
  const [userEmail, date] = chatKey.split(/_(.+)/);
  const { rows } = await pool.query(
    `SELECT role, content, tool_name, tool_args, tool_result, model, created_at
     FROM chat_messages WHERE user_email = $1 AND chat_date = $2 ORDER BY created_at`,
    [userEmail, date]
  );
  const messages = rows.map(r => {
    if (r.role === 'tool') {
      return { role: 'tool', tool: r.tool_name, args: r.tool_args, result: r.tool_result, timestamp: r.created_at?.toISOString() };
    }
    return { role: r.role, content: r.content, timestamp: r.created_at?.toISOString(), model: r.model, userName: '' };
  });
  return { userId: userEmail, date, messages };
}

async function getChatMeta(chatKey) {
  const { rows } = await pool.query('SELECT * FROM chat_meta WHERE chat_key = $1', [chatKey]);
  return rows[0] || null;
}

async function setChatMeta(chatKey, { reviewed, reviewedBy }) {
  await pool.query(
    `INSERT INTO chat_meta (chat_key, reviewed, reviewed_by, reviewed_at) VALUES ($1, $2, $3, NOW())
     ON CONFLICT (chat_key) DO UPDATE SET reviewed = $2, reviewed_by = $3, reviewed_at = NOW()`,
    [chatKey, reviewed, reviewedBy]
  );
}

// ── Escalations ──────────────────────────────────────────

async function saveEscalation(escalation) {
  await pool.query(
    'INSERT INTO escalations (id, reason, context, status) VALUES ($1, $2, $3, $4)',
    [escalation.id, escalation.reason, escalation.context, escalation.status || 'pending']
  );
}

async function listEscalations() {
  const { rows } = await pool.query('SELECT * FROM escalations ORDER BY created_at DESC LIMIT 500');
  return rows.map(r => ({ ...r, timestamp: r.created_at?.toISOString() }));
}

module.exports = {
  pool, initDB,
  loadUsers, findUserByEmail, upsertUser, updateUser, deleteUser,
  saveChatMessage, listChats, getChatDetail, getChatMeta, setChatMeta,
  saveEscalation, listEscalations,
};
