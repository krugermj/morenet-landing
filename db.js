/**
 * PostgreSQL storage layer for NEX Portal.
 * Conversation-based chat storage with review attribution.
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

      CREATE TABLE IF NOT EXISTS conversations (
        id TEXT PRIMARY KEY,
        user_email TEXT NOT NULL,
        user_name TEXT DEFAULT '',
        title TEXT DEFAULT 'New conversation',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_conv_user ON conversations(user_email);

      CREATE TABLE IF NOT EXISTS chat_messages (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        user_name TEXT DEFAULT '',
        chat_date DATE DEFAULT CURRENT_DATE,
        conversation_id TEXT,
        role TEXT NOT NULL,
        content TEXT,
        tool_name TEXT,
        tool_args JSONB,
        tool_result TEXT,
        model TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_chat_user_date ON chat_messages(user_email, chat_date);
      CREATE INDEX IF NOT EXISTS idx_chat_conversation ON chat_messages(conversation_id);

      CREATE TABLE IF NOT EXISTS escalations (
        id TEXT PRIMARY KEY,
        reason TEXT,
        context TEXT,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS chat_meta (
        chat_key TEXT PRIMARY KEY,
        conversation_id TEXT,
        reviewed BOOLEAN DEFAULT FALSE,
        reviewed_by TEXT,
        reviewer_name TEXT,
        review_notes TEXT,
        reviewed_at TIMESTAMPTZ
      );
      CREATE INDEX IF NOT EXISTS idx_chat_meta_conv ON chat_meta(conversation_id);
    `);

    // Migration: add conversation_id column if missing (for existing installs)
    await client.query(`
      DO $$ BEGIN
        ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS conversation_id TEXT;
      EXCEPTION WHEN duplicate_column THEN NULL;
      END $$;
    `).catch(() => {});

    await client.query(`
      DO $$ BEGIN
        ALTER TABLE chat_meta ADD COLUMN IF NOT EXISTS conversation_id TEXT;
        ALTER TABLE chat_meta ADD COLUMN IF NOT EXISTS reviewer_name TEXT;
        ALTER TABLE chat_meta ADD COLUMN IF NOT EXISTS review_notes TEXT;
      EXCEPTION WHEN duplicate_column THEN NULL;
      END $$;
    `).catch(() => {});

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

// ── Conversations ────────────────────────────────────────

async function createConversation(id, userEmail, userName) {
  const { rows } = await pool.query(
    `INSERT INTO conversations (id, user_email, user_name) VALUES ($1, $2, $3) RETURNING *`,
    [id, userEmail, userName || '']
  );
  return rows[0];
}

async function listConversations(userEmail, limit = 20) {
  const { rows } = await pool.query(
    `SELECT c.id, c.user_email, c.user_name, c.title, c.created_at, c.updated_at,
       (SELECT COUNT(*) FROM chat_messages WHERE conversation_id = c.id AND role IN ('user','assistant')) as message_count
     FROM conversations c
     WHERE c.user_email = $1
     ORDER BY c.updated_at DESC
     LIMIT $2`,
    [userEmail, limit]
  );
  return rows.map(r => ({
    id: r.id,
    userEmail: r.user_email,
    userName: r.user_name,
    title: r.title,
    messageCount: parseInt(r.message_count),
    createdAt: r.created_at?.toISOString(),
    updatedAt: r.updated_at?.toISOString(),
  }));
}

async function getConversationMessages(conversationId) {
  const { rows } = await pool.query(
    `SELECT role, content, tool_name, tool_args, tool_result, model, user_name, created_at
     FROM chat_messages WHERE conversation_id = $1 ORDER BY created_at`,
    [conversationId]
  );
  return rows.map(r => {
    if (r.role === 'tool') {
      return { role: 'tool', tool: r.tool_name, args: r.tool_args, result: r.tool_result, timestamp: r.created_at?.toISOString() };
    }
    return { role: r.role, content: r.content, timestamp: r.created_at?.toISOString(), model: r.model, userName: r.user_name || '' };
  });
}

async function updateConversationTitle(id, title) {
  await pool.query('UPDATE conversations SET title = $2 WHERE id = $1', [id, title]);
}

async function deleteConversation(conversationId) {
  await pool.query('DELETE FROM chat_messages WHERE conversation_id = $1', [conversationId]);
  await pool.query('DELETE FROM chat_meta WHERE conversation_id = $1', [conversationId]);
  await pool.query('DELETE FROM conversations WHERE id = $1', [conversationId]);
}

async function getConversationOwner(conversationId) {
  const { rows } = await pool.query('SELECT user_email FROM conversations WHERE id = $1', [conversationId]);
  return rows[0]?.user_email || null;
}

// ── Chat Messages ────────────────────────────────────────

async function saveChatMessage({ userEmail, userName, role, content, toolName, toolArgs, toolResult, model, conversationId }) {
  await pool.query(
    `INSERT INTO chat_messages (user_email, user_name, chat_date, conversation_id, role, content, tool_name, tool_args, tool_result, model)
     VALUES ($1, $2, CURRENT_DATE, $3, $4, $5, $6, $7, $8, $9)`,
    [userEmail, userName || '', conversationId || null, role, content || null, toolName || null,
     toolArgs ? JSON.stringify(toolArgs) : null, toolResult ? toolResult.substring(0, 4000) : null, model || null]
  );
  // Update conversation timestamp
  if (conversationId) {
    await pool.query('UPDATE conversations SET updated_at = NOW() WHERE id = $1', [conversationId]);
  }
}

// ── Admin Chat Functions ─────────────────────────────────

async function listChats(limit = 50, showReviewed = false) {
  // List conversations with review status
  const { rows } = await pool.query(
    `SELECT c.id, c.user_email, c.user_name, c.title, c.created_at, c.updated_at,
       (SELECT COUNT(*) FROM chat_messages WHERE conversation_id = c.id) as message_count,
       cm.reviewed, cm.reviewed_by, cm.reviewer_name
     FROM conversations c
     LEFT JOIN chat_meta cm ON cm.conversation_id = c.id
     ORDER BY c.updated_at DESC
     LIMIT $1`,
    [limit]
  );

  const results = [];
  for (const r of rows) {
    const reviewed = r.reviewed || false;
    if (!showReviewed && reviewed) continue;
    results.push({
      conversationId: r.id,
      userId: r.user_email,
      userName: r.user_name || '',
      title: r.title || 'New conversation',
      messageCount: parseInt(r.message_count),
      lastMessage: r.updated_at?.toISOString(),
      reviewed,
      reviewedBy: r.reviewed_by || null,
      reviewerName: r.reviewer_name || null,
    });
  }

  // Also include legacy messages (no conversation_id) grouped by user+date
  const { rows: legacyRows } = await pool.query(
    `SELECT user_email, chat_date, COUNT(*) as message_count, MAX(created_at) as last_message
     FROM chat_messages WHERE conversation_id IS NULL
     GROUP BY user_email, chat_date
     ORDER BY MAX(created_at) DESC LIMIT 50`
  );
  for (const r of legacyRows) {
    const chatKey = `${r.user_email}_${r.chat_date.toISOString().slice(0, 10)}`;
    const meta = await getChatMeta(chatKey);
    if (!showReviewed && meta?.reviewed) continue;
    results.push({
      conversationId: chatKey,
      userId: r.user_email,
      userName: '',
      title: `Legacy: ${r.chat_date.toISOString().slice(0, 10)}`,
      messageCount: parseInt(r.message_count),
      lastMessage: r.last_message?.toISOString(),
      reviewed: meta?.reviewed || false,
      reviewedBy: meta?.reviewed_by || null,
      reviewerName: meta?.reviewer_name || null,
      legacy: true,
    });
  }

  // Sort combined results by lastMessage
  results.sort((a, b) => new Date(b.lastMessage || 0) - new Date(a.lastMessage || 0));
  return results.slice(0, limit);
}

async function getChatDetail(conversationId) {
  // Check if it's a legacy chat key (email_date format)
  if (conversationId.includes('_') && conversationId.includes('@')) {
    const [userEmail, date] = conversationId.split(/_(.+)/);
    const { rows } = await pool.query(
      `SELECT role, content, tool_name, tool_args, tool_result, model, user_name, created_at
       FROM chat_messages WHERE user_email = $1 AND chat_date = $2 AND conversation_id IS NULL ORDER BY created_at`,
      [userEmail, date]
    );
    const messages = rows.map(r => {
      if (r.role === 'tool') {
        return { role: 'tool', tool: r.tool_name, args: r.tool_args, result: r.tool_result, timestamp: r.created_at?.toISOString() };
      }
      return { role: r.role, content: r.content, timestamp: r.created_at?.toISOString(), model: r.model, userName: r.user_name || '' };
    });
    return { userId: userEmail, date, messages, legacy: true };
  }

  // Modern conversation
  const conv = await pool.query('SELECT * FROM conversations WHERE id = $1', [conversationId]);
  if (conv.rows.length === 0) return null;
  const messages = await getConversationMessages(conversationId);
  return {
    conversationId,
    userId: conv.rows[0].user_email,
    userName: conv.rows[0].user_name,
    title: conv.rows[0].title,
    date: conv.rows[0].created_at?.toISOString()?.slice(0, 10),
    messages,
  };
}

async function getChatMeta(key) {
  // Try by conversation_id first, then by chat_key
  let { rows } = await pool.query('SELECT * FROM chat_meta WHERE conversation_id = $1', [key]);
  if (rows.length === 0) {
    ({ rows } = await pool.query('SELECT * FROM chat_meta WHERE chat_key = $1', [key]));
  }
  return rows[0] || null;
}

async function setChatMeta(key, { reviewed, reviewedBy, reviewerName, reviewNotes }) {
  await pool.query(
    `INSERT INTO chat_meta (chat_key, conversation_id, reviewed, reviewed_by, reviewer_name, review_notes, reviewed_at)
     VALUES ($1, $1, $2, $3, $4, $5, NOW())
     ON CONFLICT (chat_key) DO UPDATE SET
       reviewed = $2, reviewed_by = $3, reviewer_name = $4, review_notes = COALESCE($5, chat_meta.review_notes), reviewed_at = NOW()`,
    [key, reviewed, reviewedBy || null, reviewerName || null, reviewNotes || null]
  );
}

// List unreviewed conversations with messages (for automated review cron)
async function listUnreviewedConversations() {
  const { rows } = await pool.query(
    `SELECT c.id, c.user_email, c.user_name, c.title, c.created_at, c.updated_at
     FROM conversations c
     LEFT JOIN chat_meta cm ON cm.conversation_id = c.id
     WHERE cm.reviewed IS NULL OR cm.reviewed = false
     ORDER BY c.updated_at DESC
     LIMIT 100`
  );

  const results = [];
  for (const r of rows) {
    const messages = await getConversationMessages(r.id);
    results.push({
      conversationId: r.id,
      userEmail: r.user_email,
      userName: r.user_name,
      title: r.title,
      createdAt: r.created_at?.toISOString(),
      updatedAt: r.updated_at?.toISOString(),
      messages,
    });
  }
  return results;
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
  createConversation, listConversations, getConversationMessages,
  updateConversationTitle, deleteConversation, getConversationOwner,
  saveChatMessage, listChats, getChatDetail, getChatMeta, setChatMeta,
  listUnreviewedConversations,
  saveEscalation, listEscalations,
};
