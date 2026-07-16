// server.js – Karma.cc (Full LuauProtect Clone)
// Complete dashboard, fixed OAuth, key system, loader, panels

const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');
const session = require('express-session');
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const {
  Client,
  GatewayIntentBits,
  EmbedBuilder,
  Partials,
  PresenceUpdateStatus,
  ActivityType,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  ModalBuilder,
  TextInputBuilder,
  TextInputStyle,
} = require('discord.js');

// ============ ENVIRONMENT ============
const DISCORD_TOKEN = process.env.DISCORD_TOKEN;
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const GUILD_ID = process.env.GUILD_ID;
const DATABASE_PATH = process.env.DATABASE_PATH || './data.sqlite';
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || 'https://karma.cc';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const OWNER_ID = process.env.OWNER_ID || 'YOUR_DISCORD_ID_HERE';
const BRAND_COLOR = parseInt(process.env.BRAND_COLOR) || 0xFFD700;
const COOLDOWN_MS = 24 * 60 * 60 * 1000;

if (!DISCORD_TOKEN || !CLIENT_ID || !CLIENT_SECRET || !PUBLIC_BASE_URL) {
  console.error("Missing DISCORD_TOKEN, CLIENT_ID, CLIENT_SECRET, or PUBLIC_BASE_URL.");
  process.exit(1);
}

console.log('Karma.cc (Full LuauProtect Clone) starting...');

const db = new Database(DATABASE_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  discord_id TEXT UNIQUE,
  username TEXT,
  email TEXT UNIQUE,
  password_hash TEXT,
  password_salt TEXT,
  avatar TEXT,
  access_token TEXT,
  provider TEXT,
  recovery_token TEXT,
  recovery_expires TEXT,
  deleted_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scripts (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  code TEXT,
  obfuscated_code TEXT,
  version TEXT DEFAULT '1.0.0',
  status TEXT DEFAULT 'active',
  ffa_mode INTEGER DEFAULT 0,
  compress_mode INTEGER DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS keys (
  id TEXT PRIMARY KEY,
  script_id TEXT NOT NULL,
  panel_id TEXT,
  user_id TEXT NOT NULL,
  key TEXT UNIQUE NOT NULL,
  hwid TEXT,
  note TEXT,
  expires_at TEXT,
  resettable TEXT,
  claimed_by TEXT,
  claimed_tag TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at TEXT,
  FOREIGN KEY(script_id) REFERENCES scripts(id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS banned_hwids (
  hwid TEXT PRIMARY KEY,
  reason TEXT,
  banned_by TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS panels (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  channel_id TEXT NOT NULL,
  script_id TEXT NOT NULL,
  hwid_cooldown INTEGER DEFAULT 180,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(script_id) REFERENCES scripts(id)
);

CREATE TABLE IF NOT EXISTS sessions (
  sid TEXT PRIMARY KEY,
  sess TEXT NOT NULL,
  expire INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS whitelist (
  id TEXT PRIMARY KEY,
  script_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  key TEXT UNIQUE NOT NULL,
  discord_id TEXT NOT NULL,
  username TEXT,
  hwid TEXT,
  expires_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(script_id) REFERENCES scripts(id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_keys_script_id ON keys(script_id);
CREATE INDEX IF NOT EXISTS idx_keys_user_id ON keys(user_id);
CREATE INDEX IF NOT EXISTS idx_scripts_user_id ON scripts(user_id);
CREATE INDEX IF NOT EXISTS idx_panels_user_id ON panels(user_id);
CREATE INDEX IF NOT EXISTS idx_keys_key ON keys(key);
`);

// ============ HELPERS ============
function makeId(prefix = 'script') { return `${prefix}_${crypto.randomBytes(8).toString('hex')}`; }

function generateKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < 16; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

function maskKey(key) { return key ? key.substring(0, 8) + '...' + key.substring(key.length - 4) : 'Invalid'; }
function addHours(hours) { return (hours && hours > 0) ? new Date(Date.now() + hours * 3600000).toISOString() : null; }
function publicBaseUrl() { return PUBLIC_BASE_URL.replace(/\/$/, ''); }
function escapeHtml(s) { return String(s).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#039;'); }
function getSessionUser(req) { return req.session.user || null; }
function requireAuth(req, res, next) { if (req.session.user) return next(); res.redirect('/'); }
function formatExpiry(e) { return e ? new Date(e).toLocaleDateString() + ' ' + new Date(e).toLocaleTimeString() : 'Permanent'; }

function hashPassword(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) reject(err);
      resolve(derivedKey.toString('hex'));
    });
  });
}

function generateSalt() {
  return crypto.randomBytes(16).toString('hex');
}

// ============ EXPRESS APP ============
const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
	
// ============ FIXED SESSION & PROXY ============
app.set('trust proxy', 1);

// Custom session store using better-sqlite3
class SQLiteSessionStore extends session.Store {
  constructor(db) {
    super();
    this.db = db;
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        sid TEXT PRIMARY KEY,
        sess TEXT NOT NULL,
        expire INTEGER NOT NULL
      )
    `);
  }

  get(sid, callback) {
    try {
      const row = this.db.prepare('SELECT sess FROM sessions WHERE sid = ? AND expire > ?').get(sid, Date.now());
      if (row) {
        callback(null, JSON.parse(row.sess));
      } else {
        callback(null, null);
      }
    } catch (err) {
      callback(err);
    }
  }

  set(sid, sess, callback) {
    try {
      const expire = sess.cookie?.expires ? new Date(sess.cookie.expires).getTime() : Date.now() + 86400000;
      this.db.prepare('INSERT OR REPLACE INTO sessions (sid, sess, expire) VALUES (?, ?, ?)')
        .run(sid, JSON.stringify(sess), expire);
      callback(null);
    } catch (err) {
      callback(err);
    }
  }

  destroy(sid, callback) {
    try {
      this.db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid);
      callback(null);
    } catch (err) {
      callback(err);
    }
  }

  touch(sid, sess, callback) {
    try {
      const expire = sess.cookie?.expires ? new Date(sess.cookie.expires).getTime() : Date.now() + 86400000;
      this.db.prepare('UPDATE sessions SET expire = ? WHERE sid = ?').run(expire, sid);
      callback(null);
    } catch (err) {
      callback(err);
    }
  }
}

app.use(session({
  store: new SQLiteSessionStore(db),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: PUBLIC_BASE_URL.startsWith('https'), 
    maxAge: 7 * 24 * 60 * 60 * 1000,
    sameSite: PUBLIC_BASE_URL.startsWith('https') ? 'none' : 'lax',
    httpOnly: true
  }
}));

// ============ API ROUTES ============
app.get('/api/data', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.json({ error: 'Not authenticated' });
  const scripts = db.prepare('SELECT * FROM scripts WHERE user_id = ? AND deleted_at IS NULL ORDER BY created_at DESC').all(user.id);
  const panels = db.prepare('SELECT * FROM panels WHERE user_id = ? ORDER BY created_at DESC').all(user.id);
  const keys = db.prepare('SELECT * FROM keys WHERE user_id = ? ORDER BY created_at DESC').all(user.id);
  const banned = db.prepare('SELECT * FROM banned_hwids ORDER BY created_at DESC').all();
  const whitelist = db.prepare('SELECT * FROM whitelist WHERE user_id = ? ORDER BY created_at DESC').all(user.id);
  res.json({ scripts, panels, keys, bannedHWIDs: banned, whitelist, serverTime: Date.now() });
});

app.post('/api/create-script', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { name, code, compressMode } = req.body;
  if (!name || !code) return res.status(400).json({ error: 'Missing name or code' });
  const id = makeId('script');
  db.prepare(`INSERT INTO scripts (id, user_id, name, code, version, status, compress_mode)
              VALUES (?, ?, ?, ?, '1.0.0', 'active', ?)`).run(id, user.id, name, code, compressMode ? 1 : 0);
  res.json({ success: true, id });
});

app.post('/api/update-script', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { id, name, code } = req.body;
  if (!id || !name || !code) return res.status(400).json({ error: 'Missing fields' });
  const existing = db.prepare('SELECT * FROM scripts WHERE id = ? AND user_id = ?').get(id, user.id);
  if (!existing) return res.status(404).json({ error: 'Script not found' });
  db.prepare('UPDATE scripts SET name = ?, code = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?')
    .run(name, code, id, user.id);
  res.json({ success: true });
});

app.get('/api/script/:id', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const script = db.prepare('SELECT * FROM scripts WHERE id = ? AND user_id = ?').get(req.params.id, user.id);
  if (!script) return res.status(404).json({ error: 'Script not found' });
  res.json({ script });
});

app.put('/api/scripts/:id/toggle', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { id } = req.params;
  const script = db.prepare('SELECT * FROM scripts WHERE id = ? AND user_id = ?').get(id, user.id);
  if (!script) return res.status(404).json({ error: 'Script not found' });
  const newStatus = script.status === 'active' ? 'disabled' : 'active';
  db.prepare('UPDATE scripts SET status = ? WHERE id = ? AND user_id = ?').run(newStatus, id, user.id);
  res.json({ success: true, status: newStatus });
});

app.put('/api/scripts/:id/ffa', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { id } = req.params;
  const script = db.prepare('SELECT * FROM scripts WHERE id = ? AND user_id = ?').get(id, user.id);
  if (!script) return res.status(404).json({ error: 'Script not found' });
  const newFfa = script.ffa_mode ? 0 : 1;
  db.prepare('UPDATE scripts SET ffa_mode = ? WHERE id = ? AND user_id = ?').run(newFfa, id, user.id);
  res.json({ success: true, ffa_mode: newFfa });
});

app.post('/api/delete-script', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { id } = req.body;
  db.prepare('DELETE FROM scripts WHERE id = ? AND user_id = ?').run(id, user.id);
  res.json({ success: true });
});

app.post('/api/create-panel', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { name, description, channelId, scriptId, hwidCooldown } = req.body;
  if (!name || !channelId || !scriptId) return res.status(400).json({ error: 'Missing fields' });
  const id = makeId('panel');
  db.prepare(`INSERT INTO panels (id, user_id, name, description, channel_id, script_id, hwid_cooldown)
              VALUES (?, ?, ?, ?, ?, ?, ?)`).run(id, user.id, name, description || '', channelId, scriptId, hwidCooldown || 180);
  res.json({ success: true, id });
});

app.post('/api/update-panel', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { id, name, description, channelId, scriptId, hwidCooldown } = req.body;
  if (!id || !name || !channelId || !scriptId) return res.status(400).json({ error: 'Missing fields' });
  const existing = db.prepare('SELECT * FROM panels WHERE id = ? AND user_id = ?').get(id, user.id);
  if (!existing) return res.status(404).json({ error: 'Panel not found' });
  db.prepare('UPDATE panels SET name = ?, description = ?, channel_id = ?, script_id = ?, hwid_cooldown = ? WHERE id = ? AND user_id = ?')
    .run(name, description || '', channelId, scriptId, hwidCooldown || 180, id, user.id);
  res.json({ success: true });
});

app.post('/api/delete-panel', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { id } = req.body;
  db.prepare('DELETE FROM panels WHERE id = ? AND user_id = ?').run(id, user.id);
  res.json({ success: true });
});

app.post('/api/send-panel', async (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { panelId } = req.body;
  const panel = db.prepare('SELECT * FROM panels WHERE id = ? AND user_id = ?').get(panelId, user.id);
  if (!panel) return res.status(404).json({ error: 'Panel not found' });
  const script = db.prepare('SELECT * FROM scripts WHERE id = ?').get(panel.script_id);
  if (!script) return res.status(404).json({ error: 'Script not found' });
  
  try {
    const embed = new EmbedBuilder()
      .setColor(BRAND_COLOR)
      .setTitle(`🔱 ${panel.name}`)
      .setDescription(panel.description || 'Premium script protection with premium security')
      .addFields(
        { name: '📜 Script', value: script.name, inline: true },
        { name: '🛡️ Status', value: script.status === 'active' ? '✅ Active' : '❌ Disabled', inline: true },
        { name: '⏳ HWID Cooldown', value: `${panel.hwid_cooldown}s`, inline: true }
      )
      .setFooter({ text: 'Karma.cc', iconURL: 'https://cdn.discordapp.com/embed/avatars/0.png' })
      .setTimestamp();
    
    const row1 = new ActionRowBuilder().addComponents(
      new ButtonBuilder().setCustomId(`view_${script.id}`).setLabel('📋 View Script').setStyle(ButtonStyle.Primary),
      new ButtonBuilder().setCustomId(`redeem_${script.id}`).setLabel('🔑 Redeem Key').setStyle(ButtonStyle.Success)
    );
    const row2 = new ActionRowBuilder().addComponents(
      new ButtonBuilder().setCustomId(`keys_${script.id}`).setLabel('🔐 Keys').setStyle(ButtonStyle.Secondary),
      new ButtonBuilder().setCustomId(`loader_${script.id}`).setLabel('⚡ Loader').setStyle(ButtonStyle.Secondary)
    );
    const row3 = new ActionRowBuilder().addComponents(
      new ButtonBuilder().setCustomId(`resethwid_${script.id}`).setLabel('🔄 Reset HWID').setStyle(ButtonStyle.Danger)
    );
    
    const channel = await client.channels.fetch(panel.channel_id);
    await channel.send({ embeds: [embed], components: [row1, row2, row3] });
    res.json({ success: true });
  } catch (e) {
    console.error('Send panel error:', e);
    res.status(500).json({ error: 'Failed to send panel' });
  }
});

app.post('/api/generate-key', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { panelId, durationHours, note } = req.body;
  if (!panelId) return res.status(400).json({ error: 'Panel ID required' });
  const panel = db.prepare('SELECT * FROM panels WHERE id = ? AND user_id = ?').get(panelId, user.id);
  if (!panel) return res.status(404).json({ error: 'Panel not found' });
  const key = generateKey();
  const expiresAt = durationHours > 0 ? addHours(durationHours) : null;
  const id = makeId('key');
  db.prepare(`INSERT INTO keys (id, script_id, panel_id, user_id, key, note, expires_at)
              VALUES (?, ?, ?, ?, ?, ?, ?)`).run(id, panel.script_id, panel.id, user.id, key, note || '', expiresAt);
  res.json({ success: true, key });
});

app.post('/api/delete-key', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { key } = req.body;
  db.prepare('DELETE FROM keys WHERE key = ? AND user_id = ?').run(key, user.id);
  res.json({ success: true });
});

app.post('/api/add-time-all', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { hours } = req.body;
  if (!hours || isNaN(hours)) return res.status(400).json({ error: 'Invalid hours' });
  const keys = db.prepare('SELECT * FROM keys WHERE user_id = ? AND expires_at IS NOT NULL').all(user.id);
  for (const k of keys) {
    const currentExpiry = new Date(k.expires_at);
    currentExpiry.setHours(currentExpiry.getHours() + parseInt(hours));
    db.prepare('UPDATE keys SET expires_at = ? WHERE key = ?').run(currentExpiry.toISOString(), k.key);
  }
  res.json({ success: true });
});

app.post('/api/ban-hwid', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { hwid } = req.body;
  if (!hwid) return res.status(400).json({ error: 'HWID required' });
  db.prepare('INSERT OR REPLACE INTO banned_hwids (hwid, banned_by) VALUES (?, ?)').run(hwid, user.id);
  res.json({ success: true });
});

app.post('/api/unban-hwid', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { hwid } = req.body;
  if (!hwid) return res.status(400).json({ error: 'HWID required' });
  db.prepare('DELETE FROM banned_hwids WHERE hwid = ?').run(hwid);
  res.json({ success: true });
});

app.post('/api/delete-whitelist', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { id } = req.body;
  if (!id) return res.status(400).json({ error: 'ID required' });
  const entry = db.prepare('SELECT * FROM whitelist WHERE id = ? AND user_id = ?').get(id, user.id);
  if (!entry) return res.status(404).json({ error: 'Entry not found' });
  db.prepare('DELETE FROM whitelist WHERE id = ? AND user_id = ?').run(id, user.id);
  db.prepare('DELETE FROM keys WHERE key = ? AND user_id = ?').run(entry.key, user.id);
  res.json({ success: true });
});

app.post('/api/delete-account', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { confirm } = req.body;
  if (confirm !== 'DELETE') return res.status(400).json({ error: 'Confirmation required' });
  db.prepare('UPDATE users SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);
  req.session.destroy();
  res.json({ success: true });
});

app.post('/api/initiate-recovery', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  const user = db.prepare('SELECT * FROM users WHERE email = ? AND deleted_at IS NULL').get(email);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  db.prepare('UPDATE users SET recovery_token = ?, recovery_expires = ? WHERE id = ?').run(token, expires, user.id);
  const recoveryLink = `${publicBaseUrl()}/api/recover-account?token=${token}`;
  console.log(`[RECOVERY] User: ${user.username}, Link: ${recoveryLink}`);
  res.json({ success: true, message: 'Recovery link generated. Check console or your email.' });
});

app.get('/api/recover-account', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send('Missing token');
  const user = db.prepare('SELECT * FROM users WHERE recovery_token = ? AND recovery_expires > CURRENT_TIMESTAMP AND deleted_at IS NULL').get(token);
  if (!user) return res.status(404).send('Invalid or expired token');
  req.session.user = {
    id: user.id,
    discord_id: user.discord_id,
    username: user.username,
    email: user.email,
    avatar: user.avatar
  };
  db.prepare('UPDATE users SET recovery_token = NULL, recovery_expires = NULL WHERE id = ?').run(user.id);
  res.redirect('/dashboard');
});

app.post('/api/auth/email/register', async (req, res) => {
  const { email, username, password } = req.body;
  if (!email || !username || !password) return res.status(400).json({ error: 'Missing fields' });
  const existing = db.prepare('SELECT * FROM users WHERE email = ? OR username = ?').get(email, username);
  if (existing) return res.status(400).json({ error: 'Email or username already taken.' });
  const salt = generateSalt();
  const hash = await hashPassword(password, salt);
  const id = `user_${crypto.randomBytes(8).toString('hex')}`;
  db.prepare(`INSERT INTO users (id, username, email, password_hash, password_salt, provider) VALUES (?, ?, ?, ?, ?, ?)`).run(id, username, email, hash, salt, 'email');
  res.json({ success: true, message: 'Account created. Please login.' });
});

app.post('/api/auth/email/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  const user = db.prepare('SELECT * FROM users WHERE email = ? AND deleted_at IS NULL').get(email);
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });
  const hash = await hashPassword(password, user.password_salt);
  if (hash !== user.password_hash) return res.status(400).json({ error: 'Invalid credentials' });
  req.session.user = {
    id: user.id,
    discord_id: user.discord_id,
    username: user.username,
    email: user.email,
    avatar: user.avatar
  };
  res.json({ success: true });
});

// ============ FIXED DISCORD OAUTH ============
app.get('/api/auth/discord', (req, res) => {
  const state = crypto.randomBytes(18).toString('hex');
  req.session.oauth_state = state;
  req.session.save((err) => {
    if (err) console.error('Session save error:', err);
    const redirectUri = `${publicBaseUrl()}/api/auth/discord/callback`;
    const params = new URLSearchParams({
      client_id: CLIENT_ID,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: 'identify guilds',
      state: state
    });
    res.redirect(`https://discord.com/oauth2/authorize?${params.toString()}`);
  });
});

app.get('/api/auth/discord/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code || !state) return res.status(400).send('Missing code or state');
  
  if (state !== req.session.oauth_state) {
    console.warn(`OAuth state mismatch: received ${state}, expected ${req.session.oauth_state}`);
    return res.status(403).send('Invalid state parameter');
  }
  
  try {
    const redirectUri = `${publicBaseUrl()}/api/auth/discord/callback`;
    const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: 'authorization_code',
        code: String(code),
        redirect_uri: redirectUri
      })
    });
    const tokenData = await tokenResponse.json();
    if (!tokenResponse.ok) throw new Error('Failed to get token');
    
    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const user = await userResponse.json();
    
    let dbUser = db.prepare('SELECT * FROM users WHERE discord_id = ? AND deleted_at IS NULL').get(user.id);
    if (!dbUser) {
      const id = `user_${crypto.randomBytes(8).toString('hex')}`;
      db.prepare(`INSERT INTO users (id, discord_id, username, avatar, access_token, provider)
                  VALUES (?, ?, ?, ?, ?, ?)`).run(id, user.id, user.username, user.avatar || '', tokenData.access_token, 'discord');
      dbUser = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(user.id);
    } else {
      db.prepare('UPDATE users SET username = ?, avatar = ?, access_token = ?, updated_at = CURRENT_TIMESTAMP WHERE discord_id = ?')
        .run(user.username, user.avatar || '', tokenData.access_token, user.id);
    }
    
    req.session.user = {
      id: dbUser.id,
      discord_id: user.id,
      username: user.username,
      global_name: user.global_name,
      avatar: user.avatar,
      email: dbUser.email || null
    };
    req.session.save((err) => {
      if (err) console.error('Session save error:', err);
      res.redirect('/dashboard');
    });
  } catch (e) {
    console.error('Auth error:', e);
    res.status(500).send('Authentication failed');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.get('/health', (req, res) => res.json({ ok: true, name: 'Karma.cc' }));

// ============ FULL DASHBOARD HTML (EMBEDDED) ============
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Karma.cc</title>
  <meta property="og:site_name" content="Karma.cc" />
  <meta property="og:title" content="Karma.cc - Premium Script Protection" />
  <meta property="og:description" content="Protect your scripts with premium security" />
  <meta property="og:url" content="${publicBaseUrl()}/" />
  <meta name="theme-color" content="#FFD700" />
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    :root {
      --bg: #0a0a08;
      --gold: #FFD700;
      --gold-dark: #B8860B;
      --gold-glow: rgba(255,215,0,0.15);
      --text: #f5f0e8;
      --muted: #a89880;
      --border: rgba(255,215,0,0.15);
      --card: rgba(20,18,10,0.85);
    }
    * { margin:0; padding:0; box-sizing:border-box; }
    body {
      font-family: 'Inter', system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background-image: radial-gradient(ellipse at 50% 0%, rgba(255,215,0,0.06) 0%, transparent 70%);
    }
    .container { max-width:1200px; margin:0 auto; padding:20px; width:100%; }
    .glass {
      background: var(--card);
      backdrop-filter: blur(20px);
      border: 1px solid var(--border);
      border-radius: 24px;
      padding: 48px 40px;
      max-width: 420px;
      width: 100%;
      margin: 0 auto;
      box-shadow: 0 0 60px rgba(255,215,0,0.05);
      text-align: center;
      position: relative;
      overflow: hidden;
    }
    .glass::before {
      content: '';
      position: absolute;
      top: -50%;
      left: -50%;
      width: 200%;
      height: 200%;
      background: conic-gradient(from 0deg, transparent, rgba(255,215,0,0.05), transparent, rgba(255,215,0,0.05), transparent);
      animation: spin 20s linear infinite;
      pointer-events: none;
    }
    @keyframes spin { 100% { transform:rotate(360deg); } }
    .logo { margin-bottom:24px; position:relative; z-index:1; }
    .logo svg { width:56px; height:56px; color:var(--gold); filter:drop-shadow(0 0 30px rgba(255,215,0,0.2)); }
    h1 { font-size:28px; font-weight:800; letter-spacing:-0.5px; margin-bottom:8px; position:relative; z-index:1; }
    h1 span { color:var(--gold); text-shadow: 0 0 30px rgba(255,215,0,0.2); }
    .sub { color:var(--muted); font-size:14px; margin-bottom:28px; position:relative; z-index:1; }
    .btn { display:inline-flex; align-items:center; justify-content:center; gap:12px; width:100%; padding:16px 24px; border:none; border-radius:14px; font-weight:700; font-size:16px; cursor:pointer; transition:all 0.3s; position:relative; z-index:1; text-decoration:none; }
    .btn-gold {
      background: linear-gradient(135deg, #FFD700, #B8860B);
      color: #0a0a08;
      box-shadow: 0 4px 30px rgba(255,215,0,0.3);
    }
    .btn-gold:hover { transform:translateY(-3px); box-shadow: 0 8px 40px rgba(255,215,0,0.5); }
    .btn-discord { background:#5865F2; color:white; }
    .btn-discord:hover { background:#4752C4; transform:translateY(-3px); }
    .btn-outline {
      background:rgba(255,215,0,0.05);
      border:1px solid var(--border);
      color:var(--text);
    }
    .btn-outline:hover { border-color:var(--gold); color:var(--gold); background:rgba(255,215,0,0.1); }
    .mt-16 { margin-top:16px; }
    .flex-col { display:flex; flex-direction:column; gap:12px; }
    .input {
      width:100%;
      background:rgba(0,0,0,0.4);
      border:1px solid var(--border);
      color:var(--text);
      padding:12px 16px;
      border-radius:10px;
      font-size:14px;
      transition:all 0.2s;
    }
    .input:focus { outline:none; border-color:var(--gold); box-shadow:0 0 0 3px rgba(255,215,0,0.1); }
    .divider { display:flex; align-items:center; gap:12px; color:var(--muted); font-size:13px; margin:16px 0; }
    .divider::before, .divider::after { content:''; flex:1; height:1px; background:var(--border); }
    .hidden { display:none; }
    .badge { display:inline-block; padding:4px 14px; border:1px solid var(--gold); border-radius:20px; font-size:11px; font-weight:600; color:var(--gold); text-transform:uppercase; letter-spacing:0.05em; margin-bottom:12px; position:relative; z-index:1; }
    .tab-btn { background:none; border:none; color:var(--muted); font-size:14px; font-weight:600; cursor:pointer; padding:8px 16px; border-radius:8px; transition:all 0.2s; }
    .tab-btn.active { color:var(--gold); background:rgba(255,215,0,0.1); }
    .tab-btn:hover { color:var(--text); }
  </style>
</head>
<body>
<div class="container">
  <div id="login-view" class="glass fade-in">
    <div class="logo">
      <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
      </svg>
    </div>
    
    <h1>Karma<span>.cc</span></h1>
    <p class="sub">Premium script protection with HWID-locked keys</p>
    <div style="display:flex;justify-content:center;gap:8px;margin-bottom:20px;">
      <button class="tab-btn active" onclick="switchTab('login')">Login</button>
      <button class="tab-btn" onclick="switchTab('register')">Register</button>
    </div>
    <div id="tab-login" class="flex-col">
      <input class="input" id="login-email" placeholder="Email" type="email">
      <input class="input" id="login-password" placeholder="Password" type="password">
      <button class="btn btn-gold" onclick="emailLogin()">Sign In</button>
      <div class="divider">or continue with</div>
      <a href="/api/auth/discord" class="btn btn-discord">
        <svg viewBox="0 0 127.14 96.36" style="width:22px;height:22px;fill:white;"><path d="M107.7,8.07A105.15,105.15,0,0,0,81.47,0a72.06,72.06,0,0,0-3.36,6.83A97.68,97.68,0,0,0,49,6.83,72.37,72.37,0,0,0,45.64,0,105.89,105.89,0,0,0,19.39,8.09C2.79,32.65-1.71,56.6.54,80.21h0A105.73,105.73,0,0,0,32.71,96.36,77.7,77.7,0,0,0,39.6,85.25a68.42,68.42,0,0,1-10.85-5.18c.91-.66,1.8-1.34,2.66-2a75.57,75.57,0,0,0,64.32,0c.87.71,1.76,1.39,2.66,2a68.68,68.68,0,0,1-10.87,5.19,77,77,0,0,0,6.89,11.1A105.25,105.25,0,0,0,126.6,80.22h0C129.24,52.84,122.09,29.11,107.7,8.07ZM42.45,65.69C36.18,65.69,31,60,31,53s5-12.74,11.43-12.74S54,46,53.89,53,48.84,65.69,42.45,65.69Zm42.24,0C78.41,65.69,73.31,60,73.31,53s5-12.74,11.43-12.74S96.1,46,96,53,91.08,65.69,84.69,65.69Z"/></svg>
        Login with Discord
      </a>
      <button class="btn btn-outline mt-16" onclick="showRecovery()">Forgot password?</button>
    </div>
    <div id="tab-register" class="flex-col hidden">
      <input class="input" id="register-username" placeholder="Username">
      <input class="input" id="register-email" placeholder="Email" type="email">
      <input class="input" id="register-password" placeholder="Password" type="password">
      <button class="btn btn-gold" onclick="emailRegister()">Create Account</button>
      <div class="divider">or</div>
      <a href="/api/auth/discord" class="btn btn-discord">
        <svg viewBox="0 0 127.14 96.36" style="width:22px;height:22px;fill:white;"><path d="M107.7,8.07A105.15,105.15,0,0,0,81.47,0a72.06,72.06,0,0,0-3.36,6.83A97.68,97.68,0,0,0,49,6.83,72.37,72.37,0,0,0,45.64,0,105.89,105.89,0,0,0,19.39,8.09C2.79,32.65-1.71,56.6.54,80.21h0A105.73,105.73,0,0,0,32.71,96.36,77.7,77.7,0,0,0,39.6,85.25a68.42,68.42,0,0,1-10.85-5.18c.91-.66,1.8-1.34,2.66-2a75.57,75.57,0,0,0,64.32,0c.87.71,1.76,1.39,2.66,2a68.68,68.68,0,0,1-10.87,5.19,77,77,0,0,0,6.89,11.1A105.25,105.25,0,0,0,126.6,80.22h0C129.24,52.84,122.09,29.11,107.7,8.07ZM42.45,65.69C36.18,65.69,31,60,31,53s5-12.74,11.43-12.74S54,46,53.89,53,48.84,65.69,42.45,65.69Zm42.24,0C78.41,65.69,73.31,60,73.31,53s5-12.74,11.43-12.74S96.1,46,96,53,91.08,65.69,84.69,65.69Z"/></svg>
        Continue with Discord
      </a>
    </div>
    <div id="recovery-view" class="hidden flex-col mt-16">
      <h3 style="font-size:18px;font-weight:600;margin-bottom:8px;">Recover Account</h3>
      <p class="sub">Enter your email to generate a recovery link.</p>
      <input class="input" id="recovery-email" placeholder="Email" type="email">
      <button class="btn btn-gold" onclick="initiateRecovery()">Generate Recovery Link</button>
      <button class="btn btn-outline mt-16" onclick="showLogin()">Back to Login</button>
    </div>
  </div>
</div>
<script>
function switchTab(tab) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-login').classList.toggle('hidden', tab !== 'login');
  document.getElementById('tab-register').classList.toggle('hidden', tab !== 'register');
  document.querySelector('.tab-btn[onclick*="' + tab + '"]').classList.add('active');
}
function showRecovery() {
  document.getElementById('tab-login').classList.add('hidden');
  document.getElementById('tab-register').classList.add('hidden');
  document.getElementById('recovery-view').classList.remove('hidden');
}
function showLogin() {
  document.getElementById('recovery-view').classList.add('hidden');
  document.getElementById('tab-login').classList.remove('hidden');
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelector('.tab-btn[onclick*="login"]').classList.add('active');
}
async function emailLogin() {
  const email = document.getElementById('login-email').value;
  const password = document.getElementById('login-password').value;
  if (!email || !password) return alert('Fill all fields.');
  const res = await fetch('/api/auth/email/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({email,password}) });
  const data = await res.json();
  if (data.success) window.location.href = '/dashboard';
  else alert(data.error);
}
async function emailRegister() {
  const username = document.getElementById('register-username').value;
  const email = document.getElementById('register-email').value;
  const password = document.getElementById('register-password').value;
  if (!username || !email || !password) return alert('Fill all fields.');
  const res = await fetch('/api/auth/email/register', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username,email,password}) });
  const data = await res.json();
  if (data.success) { alert('Account created! Please login.'); switchTab('login'); }
  else alert(data.error);
}
async function initiateRecovery() {
  const email = document.getElementById('recovery-email').value;
  if (!email) return alert('Enter your email.');
  const res = await fetch('/api/initiate-recovery', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({email}) });
  const data = await res.json();
  if (data.success) alert('Recovery link generated. Check console or your email.');
  else alert(data.error || 'Something went wrong.');
}
</script>
</body>
</html>`);
});

// ============ FULL DASHBOARD ROUTE ============
app.get('/dashboard', requireAuth, (req, res) => {
  const user = req.session.user;
  const escapedUsername = escapeHtml(user.global_name || user.username || user.email);
  const avatarUrl = user.avatar ? `https://cdn.discordapp.com/avatars/${user.discord_id}/${user.avatar}.png?size=128` : 'https://cdn.discordapp.com/embed/avatars/0.png';
  const botInviteUrl = `https://discord.com/oauth2/authorize?client_id=${CLIENT_ID}&permissions=8&scope=bot`;
  
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Karma.cc</title>
	  <meta property="og:site_name" content="Karma.cc" />
	  <meta property="og:title" content="Karma.cc - Premium Script Protection" />
	  <meta property="og:url" content="${publicBaseUrl()}/dashboard" />
	  <meta name="theme-color" content="#FFD700" />
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    :root {
      --bg-color: #0a0a08;
      --card-bg: rgba(20, 18, 10, 0.85);
      --gold: #FFD700;
      --gold-dark: #B8860B;
      --gold-glow: rgba(255, 215, 0, 0.15);
      --gold-hover: #FFC125;
      --discord: #5865F2;
      --danger: #ef4444;
      --success: #10b981;
      --text-main: #f5f0e8;
      --text-muted: #a89880;
      --border: rgba(255, 215, 0, 0.15);
    }
    * { margin:0; padding:0; box-sizing:border-box; }
    body {
      font-family: 'Inter', system-ui, sans-serif;
      background-color: var(--bg-color);
      color: var(--text-main);
      min-height: 100vh;
      -webkit-font-smoothing: antialiased;
    }
    .glass-card {
      background: var(--card-bg);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid var(--border);
      box-shadow: 0 0 60px rgba(255, 215, 0, 0.05), inset 0 0 0 1px rgba(255, 215, 0, 0.05);
    }
    .dashboard {
      display: flex;
      height: 100vh;
      overflow: hidden;
    }
    .sidebar {
      width: 260px;
      background: var(--card-bg);
      backdrop-filter: blur(16px);
      border-right: 1px solid var(--border);
      padding: 25px 18px;
      display: flex;
      flex-direction: column;
      flex-shrink: 0;
      height: 100vh;
      overflow-y: auto;
    }
    .sidebar::-webkit-scrollbar { width: 4px; }
    .sidebar::-webkit-scrollbar-thumb { background-color: var(--border); border-radius: 6px; }
    .brand {
      font-size: 20px;
      font-weight: 800;
      color: white;
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 30px;
    }
    .brand span { color: var(--gold); text-shadow: 0 0 20px rgba(255, 215, 0, 0.2); }
    .nav-item {
      color: var(--text-muted);
      padding: 12px 14px;
      border-radius: 10px;
      cursor: pointer;
      font-weight: 600;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 14px;
      margin-bottom: 2px;
    }
    .nav-item:hover { background-color: rgba(255, 215, 0, 0.05); color: var(--gold); }
    .nav-item.active { background-color: var(--gold-glow); color: var(--gold); }
    .nav-label {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--text-muted);
      padding: 12px 14px 6px;
      font-weight: 700;
      opacity: 0.5;
    }
    .main-content {
      flex: 1;
      display: flex;
      flex-direction: column;
      height: 100vh;
      overflow: hidden;
    }
    .topbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 15px 30px;
      background: var(--card-bg);
      backdrop-filter: blur(16px);
      border-bottom: 1px solid var(--border);
    }
    .user-profile {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .user-avatar {
      width: 38px;
      height: 38px;
      border-radius: 50%;
      object-fit: cover;
      border: 2px solid var(--gold);
    }
    .user-name { font-weight: 600; font-size: 14px; }
    .logout-btn { color: var(--text-muted); cursor: pointer; font-size: 13px; transition: color 0.2s; }
    .logout-btn:hover { color: var(--danger); }
    .content-scroll {
      flex: 1;
      overflow-y: auto;
      padding: 25px 30px;
    }
    .content-scroll::-webkit-scrollbar { width: 6px; }
    .content-scroll::-webkit-scrollbar-thumb { background-color: #3f3f46; border-radius: 8px; }
    .panel {
      background: var(--card-bg);
      backdrop-filter: blur(16px);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 25px;
      margin-bottom: 25px;
      box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.5);
    }
    .panel h2 { font-size: 20px; font-weight: 800; margin-bottom: 20px; }
    .panel h2 span { color: var(--gold); }
    input, textarea, select {
      width: 100%;
      background: rgba(0,0,0,0.3);
      border: 1px solid var(--border);
      color: var(--text-main);
      padding: 12px 16px;
      border-radius: 10px;
      margin-bottom: 14px;
      font-size: 14px;
      transition: all 0.2s;
    }
    input:focus, textarea:focus, select:focus {
      outline: none;
      border-color: var(--gold);
      box-shadow: 0 0 0 3px var(--gold-glow);
    }
    textarea { min-height: 120px; font-family: 'JetBrains Mono', monospace; resize: vertical; }
    select { appearance: none; background-image: url("data:image/svg+xml;charset=US-ASCII,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%22292.4%22%20height%3D%22292.4%22%3E%3Cpath%20fill%3D%22%23FFD700%22%20d%3D%22M287%2069.4a17.6%2017.6%200%200%200-13-5.4H18.4c-5%200-9.3%201.8-12.9%205.4A17.6%2017.6%200%200%200%200%2082.2c0%205%201.8%209.3%205.4%2012.9l128%20127.9c3.6%203.6%207.8%205.4%2012.8%205.4s9.2-1.8%2012.8-5.4L287%2095c3.5-3.5%205.4-7.8%205.4-12.8%200-5-1.9-9.2-5.5-12.8z%22/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 16px top 50%; background-size: 12px auto; }
    .btn {
      padding: 10px 20px;
      border: none;
      border-radius: 10px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
      font-size: 13px;
      display: inline-flex;
      align-items: center;
      gap: 8px;
    }
    .btn-gold {
      background: linear-gradient(135deg, #FFD700, #B8860B);
      color: #0a0a08;
      box-shadow: 0 4px 20px rgba(255,215,0,0.3);
    }
    .btn-gold:hover { transform: translateY(-2px); box-shadow: 0 8px 30px rgba(255,215,0,0.4); }
    .btn-danger { background: rgba(239,68,68,0.15); color: var(--danger); border: 1px solid rgba(239,68,68,0.2); }
    .btn-danger:hover { background: rgba(239,68,68,0.25); }
    .btn-success { background: rgba(16,185,129,0.15); color: var(--success); border: 1px solid rgba(16,185,129,0.2); }
    .btn-success:hover { background: rgba(16,185,129,0.25); }
    .btn-outline { background: rgba(0,0,0,0.2); border: 1px solid var(--border); color: var(--text-main); }
    .btn-outline:hover { border-color: var(--gold); color: var(--gold); }
    .scripts-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
      gap: 20px;
    }
    .script-card {
      background: rgba(0,0,0,0.2);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 18px;
      transition: all 0.3s;
    }
    .script-card:hover { border-color: var(--gold); transform: translateY(-3px); }
    .script-card .title { font-weight: 600; font-size: 15px; margin-bottom: 8px; }
    .script-card .meta { font-size: 12px; color: var(--text-muted); margin-bottom: 12px; }
    .script-card .actions { display: flex; gap: 8px; flex-wrap: wrap; }
    .script-card .actions .btn { flex: 1; padding: 8px 12px; font-size: 12px; justify-content: center; }
    .badge {
      display: inline-block;
      padding: 2px 10px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 600;
    }
    .badge-success { background: rgba(16,185,129,0.15); color: var(--success); border: 1px solid rgba(16,185,129,0.15); }
    .badge-danger { background: rgba(239,68,68,0.15); color: var(--danger); border: 1px solid rgba(239,68,68,0.15); }
    .badge-warning { background: rgba(255,215,0,0.15); color: var(--gold); border: 1px solid rgba(255,215,0,0.15); }
    .view-section { display: none; }
    .view-section.active { display: block; animation: fadeIn 0.3s ease; }
    @keyframes fadeIn { from { opacity:0; transform:translateY(10px); } to { opacity:1; transform:translateY(0); } }
    .flex { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
    .flex-between { display: flex; justify-content: space-between; align-items: center; }
    .text-muted { color: var(--text-muted); }
    .mt-16 { margin-top: 16px; }
    @media (max-width: 768px) {
      .sidebar { display: none; position: fixed; top: 0; left: 0; width: 260px; height: 100vh; z-index: 100; }
      .sidebar.open { display: flex; }
      .main-content { width: 100%; }
      .topbar { padding: 15px; }
      .content-scroll { padding: 15px; }
      .scripts-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
<div class="dashboard">
  <div class="sidebar" id="sidebar">
    <div class="brand">Karma<span>.cc</span></div>
    <div class="nav-label">Navigation</div>
    <div class="nav-item active" onclick="switchView('overview', this)">📊 Overview</div>
    <div class="nav-item" onclick="switchView('scripts', this)">📜 Scripts</div>
    <div class="nav-item" onclick="switchView('panels', this)">📋 Panels</div>
    <div class="nav-item" onclick="switchView('keys', this)">🔑 Keys</div>
    <div class="nav-item" onclick="switchView('hwids', this)">🚫 HWID Bans</div>
    <div style="margin-top: auto; padding-top: 20px; border-top: 1px solid var(--border);">
      <div class="nav-item" onclick="logout()" style="color: var(--danger);">🚪 Logout</div>
    </div>
  </div>
  
  <div class="main-content">
    <div class="topbar">
      <div style="display: flex; align-items: center; gap: 12px;">
        <button class="btn btn-outline" style="padding: 8px 12px; display: none;" id="menuToggle" onclick="toggleSidebar()">☰</button>
        <span style="font-weight: 700; font-size: 18px;">👑 Dashboard</span>
      </div>
      <div class="user-profile">
        <span class="user-name" id="displayUsername">${escapedUsername}</span>
        <img class="user-avatar" src="${avatarUrl}" alt="Avatar">
        <span class="logout-btn" onclick="logout()">Logout</span>
      </div>
    </div>
    
    <div class="content-scroll">
      <div id="view-overview" class="view-section active">
        <div class="panel">
          <h2>Welcome, <span>${escapedUsername}</span></h2>
          <p style="color: var(--text-muted);">Manage your scripts, panels, and keys from one place.</p>
          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin-top: 20px;" id="statsGrid">
            <div style="background: rgba(0,0,0,0.2); border: 1px solid var(--border); border-radius: 12px; padding: 16px; text-align: center;">
              <div style="font-size: 28px; font-weight: 900; color: var(--gold);" id="statScripts">0</div>
              <div style="font-size: 13px; color: var(--text-muted);">Scripts</div>
            </div>
            <div style="background: rgba(0,0,0,0.2); border: 1px solid var(--border); border-radius: 12px; padding: 16px; text-align: center;">
              <div style="font-size: 28px; font-weight: 900; color: var(--gold);" id="statPanels">0</div>
              <div style="font-size: 13px; color: var(--text-muted);">Panels</div>
            </div>
            <div style="background: rgba(0,0,0,0.2); border: 1px solid var(--border); border-radius: 12px; padding: 16px; text-align: center;">
              <div style="font-size: 28px; font-weight: 900; color: var(--gold);" id="statKeys">0</div>
              <div style="font-size: 13px; color: var(--text-muted);">Keys</div>
            </div>
            <div style="background: rgba(0,0,0,0.2); border: 1px solid var(--border); border-radius: 12px; padding: 16px; text-align: center;">
              <div style="font-size: 28px; font-weight: 900; color: var(--gold);" id="statBanned">0</div>
              <div style="font-size: 13px; color: var(--text-muted);">Banned HWIDs</div>
            </div>
          </div>
        </div>
        <div class="panel">
          <h3>Invite Bot</h3>
          <p style="color: var(--text-muted);">Add the Karma.cc bot to your Discord server.</p>
          <a href="${botInviteUrl}" target="_blank" class="btn btn-gold" style="display: inline-flex; margin-top: 10px;">🤖 Invite Bot</a>
        </div>
      </div>
      
      <div id="view-scripts" class="view-section">
        <div class="panel">
          <h2>Your <span>Scripts</span></h2>
          <div class="flex" style="margin-bottom: 16px;">
            <input type="text" id="scriptName" placeholder="Script name" style="flex: 1; min-width: 150px; margin: 0;">
            <label style="display: flex; align-items: center; gap: 6px; padding: 10px 14px; background: rgba(0,0,0,0.2); border: 1px solid var(--border); border-radius: 10px; cursor: pointer; font-weight: 600; font-size: 13px;">
              <input type="checkbox" id="ffaMode"> FFA Mode
            </label>
            <label style="display: flex; align-items: center; gap: 6px; padding: 10px 14px; background: rgba(0,0,0,0.2); border: 1px solid var(--border); border-radius: 10px; cursor: pointer; font-weight: 600; font-size: 13px;">
              <input type="checkbox" id="compressMode"> Compress
            </label>
            <button class="btn btn-gold" onclick="createScript()">Create</button>
          </div>
          <textarea id="scriptCode" rows="8" placeholder="Paste your Lua code here..."></textarea>
        </div>
        <div id="scriptsList" class="scripts-grid"></div>
      </div>
      
      <div id="view-panels" class="view-section">
        <div class="panel">
          <h2>Discord <span>Panels</span></h2>
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
            <input type="text" id="panelName" placeholder="Panel name">
            <input type="text" id="panelChannel" placeholder="Discord Channel ID">
          </div>
          <textarea id="panelDesc" rows="3" placeholder="Panel description..."></textarea>
          <select id="panelScript"><option value="">Select script...</option></select>
          <input type="number" id="panelCooldown" placeholder="HWID cooldown (seconds)" value="180">
          <button class="btn btn-gold" onclick="createPanel()">Create Panel</button>
        </div>
        <div id="panelsList" class="scripts-grid"></div>
      </div>
      
      <div id="view-keys" class="view-section">
        <div class="panel">
          <h2>Generate <span>Keys</span></h2>
          <select id="keyPanel"><option value="">Select panel...</option></select>
          <input type="number" id="keyDuration" placeholder="Duration (hours, 0 = permanent)" value="0">
          <input type="text" id="keyNote" placeholder="Note (optional)">
          <div style="display: flex; gap: 10px; flex-wrap: wrap;">
            <button class="btn btn-gold" onclick="generateKey()">Generate Key</button>
            <button class="btn btn-outline" onclick="addTimeAll()">Add Time to All</button>
          </div>
        </div>
        <div id="keysList" class="scripts-grid"></div>
      </div>
      
      <div id="view-hwids" class="view-section">
        <div class="panel">
          <h2>Ban <span>HWID</span></h2>
          <div class="flex">
            <input type="text" id="banHwidInput" placeholder="Enter HWID to ban" style="flex: 1; margin: 0;">
            <button class="btn btn-danger" onclick="banHwid()">Ban</button>
          </div>
        </div>
        <div id="hwidsList" class="scripts-grid"></div>
      </div>
    </div>
  </div>
</div>

<script>
let currentData = { scripts: [], panels: [], keys: [], bannedHWIDs: [] };
let serverTime = Date.now();
let editingScriptId = null;
let editingPanelId = null;

function getHeaders() { return { 'Content-Type': 'application/json' }; }

async function loadData() {
  try {
    const res = await fetch('/api/data');
    const data = await res.json();
    if (data.error) return;
    currentData = data;
    serverTime = data.serverTime || Date.now();
    renderAll();
  } catch(e) { console.error(e); }
}

function renderAll() {
  renderStats();
  renderScripts();
  renderPanels();
  renderKeys();
  renderHwids();
  updateSelects();
}

function renderStats() {
  document.getElementById('statScripts').textContent = currentData.scripts.length;
  document.getElementById('statPanels').textContent = currentData.panels.length;
  document.getElementById('statKeys').textContent = currentData.keys.length;
  document.getElementById('statBanned').textContent = currentData.bannedHWIDs.length;
}

function renderScripts() {
  const container = document.getElementById('scriptsList');
  if (!currentData.scripts.length) {
    container.innerHTML = '<div style="grid-column:1/-1;padding:30px;text-align:center;color:var(--text-muted);background:rgba(0,0,0,0.2);border-radius:12px;border:1px dashed var(--border);">No scripts yet. Create one above.</div>';
    return;
  }
  let html = '';
  for (const s of currentData.scripts) {
    const statusBadge = s.status === 'active' ? 'badge-success' : 'badge-danger';
    const statusText = s.status === 'active' ? 'Active' : 'Disabled';
    const ffaBadge = s.ffa_mode ? '<span class="badge badge-warning">FFA</span>' : '';
    const compressBadge = s.compress_mode ? '<span class="badge badge-warning">Compressed</span>' : '';
    const date = new Date(s.created_at).toLocaleDateString();
    html += '<div class="script-card">' +
      '<div class="title">' + escapeHtml(s.name) + '</div>' +
      '<div class="meta"><span class="badge ' + statusBadge + '">' + statusText + '</span> ' + ffaBadge + ' ' + compressBadge + ' <span style="margin-left:8px;">' + date + '</span></div>' +
      '<div class="actions">' +
        '<button class="btn btn-outline" onclick="toggleScript(\'' + s.id + '\')">' + (s.status==='active'?'Disable':'Enable') + '</button>' +
        '<button class="btn btn-outline" onclick="toggleFfa(\'' + s.id + '\')">' + (s.ffa_mode?'Disable FFA':'Enable FFA') + '</button>' +
        '<button class="btn btn-danger" onclick="deleteScript(\'' + s.id + '\')">Delete</button>' +
      '</div></div>';
  }
  container.innerHTML = html;
}

function renderPanels() {
  const container = document.getElementById('panelsList');
  if (!currentData.panels.length) {
    container.innerHTML = '<div style="grid-column:1/-1;padding:30px;text-align:center;color:var(--text-muted);background:rgba(0,0,0,0.2);border-radius:12px;border:1px dashed var(--border);">No panels yet. Create one above.</div>';
    return;
  }
  let html = '';
  for (const p of currentData.panels) {
    html += '<div class="script-card">' +
      '<div class="title">' + escapeHtml(p.name) + '</div>' +
      '<div class="meta">' + escapeHtml(p.description || 'No description') + '</div>' +
      '<div class="actions">' +
        '<button class="btn btn-success" onclick="sendPanel(\'' + p.id + '\')">Send to Discord</button>' +
        '<button class="btn btn-danger" onclick="deletePanel(\'' + p.id + '\')">Delete</button>' +
      '</div></div>';
  }
  container.innerHTML = html;
}

function renderKeys() {
  const container = document.getElementById('keysList');
  if (!currentData.keys.length) {
    container.innerHTML = '<div style="grid-column:1/-1;padding:30px;text-align:center;color:var(--text-muted);background:rgba(0,0,0,0.2);border-radius:12px;border:1px dashed var(--border);">No keys generated yet.</div>';
    return;
  }
  let html = '';
  for (const k of currentData.keys) {
    const expired = k.expires_at && new Date(k.expires_at).getTime() < serverTime;
    let status = 'Active', badgeClass = 'badge-success';
    if (expired) { status = 'Expired'; badgeClass = 'badge-danger'; }
    else if (k.hwid) { status = 'HWID Locked'; badgeClass = 'badge-warning'; }
    html += '<div class="script-card">' +
      '<div class="title" style="font-family:monospace;font-size:13px;color:var(--gold);">' + escapeHtml(k.key) + '</div>' +
      '<div class="meta"><span class="badge ' + badgeClass + '">' + status + '</span> ' + (k.note ? '<span style="margin-left:8px;">'+escapeHtml(k.note)+'</span>' : '') + '</div>' +
      '<div class="actions"><button class="btn btn-danger" onclick="deleteKey(\'' + k.key + '\')">Delete</button></div></div>';
  }
  container.innerHTML = html;
}

function renderHwids() {
  const container = document.getElementById('hwidsList');
  if (!currentData.bannedHWIDs.length) {
    container.innerHTML = '<div style="grid-column:1/-1;padding:30px;text-align:center;color:var(--text-muted);background:rgba(0,0,0,0.2);border-radius:12px;border:1px dashed var(--border);">No banned HWIDs.</div>';
    return;
  }
  let html = '';
  for (const h of currentData.bannedHWIDs) {
    html += '<div class="script-card">' +
      '<div class="title" style="font-family:monospace;font-size:13px;color:var(--danger);">' + escapeHtml(h.hwid) + '</div>' +
      '<div class="meta">Banned ' + new Date(h.created_at).toLocaleDateString() + '</div>' +
      '<div class="actions"><button class="btn btn-outline" onclick="unbanHwid(\'' + h.hwid + '\')">Unban</button></div></div>';
  }
  container.innerHTML = html;
}

function updateSelects() {
  const panelScript = document.getElementById('panelScript');
  panelScript.innerHTML = '<option value="">Select script...</option>';
  for (const s of currentData.scripts) {
    panelScript.innerHTML += '<option value="' + s.id + '">' + escapeHtml(s.name) + '</option>';
  }
  const keyPanel = document.getElementById('keyPanel');
  keyPanel.innerHTML = '<option value="">Select panel...</option>';
  for (const p of currentData.panels) {
    keyPanel.innerHTML += '<option value="' + p.id + '">' + escapeHtml(p.name) + '</option>';
  }
}

function switchView(view, el) {
  document.querySelectorAll('.view-section').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('view-' + view).classList.add('active');
  if (el) el.classList.add('active');
  if (window.innerWidth <= 768) document.getElementById('sidebar').classList.remove('open');
}

function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
}

async function createScript() {
  const name = document.getElementById('scriptName').value.trim();
  const code = document.getElementById('scriptCode').value;
  const compressMode = document.getElementById('compressMode').checked;
  if (!name || !code) return alert('Please enter a name and code.');
  await fetch('/api/create-script', { method:'POST', headers:getHeaders(), body:JSON.stringify({name,code,compressMode}) });
  document.getElementById('scriptName').value = '';
  document.getElementById('scriptCode').value = '';
  document.getElementById('ffaMode').checked = false;
  document.getElementById('compressMode').checked = false;
  loadData();
}

async function toggleScript(id) {
  await fetch('/api/scripts/'+id+'/toggle', { method:'PUT', headers:getHeaders() });
  loadData();
}

async function toggleFfa(id) {
  await fetch('/api/scripts/'+id+'/ffa', { method:'PUT', headers:getHeaders() });
  loadData();
}

async function deleteScript(id) {
  if (!confirm('Delete this script?')) return;
  await fetch('/api/delete-script', { method:'POST', headers:getHeaders(), body:JSON.stringify({id}) });
  loadData();
}

async function createPanel() {
  const name = document.getElementById('panelName').value.trim();
  const description = document.getElementById('panelDesc').value;
  const channelId = document.getElementById('panelChannel').value.trim();
  const scriptId = document.getElementById('panelScript').value;
  const hwidCooldown = parseInt(document.getElementById('panelCooldown').value) || 180;
  if (!name || !channelId || !scriptId) return alert('Please fill in all required fields.');
  await fetch('/api/create-panel', { method:'POST', headers:getHeaders(), body:JSON.stringify({name,description,channelId,scriptId,hwidCooldown}) });
  document.getElementById('panelName').value = '';
  document.getElementById('panelDesc').value = '';
  document.getElementById('panelChannel').value = '';
  document.getElementById('panelCooldown').value = '180';
  loadData();
}

async function sendPanel(id) {
  await fetch('/api/send-panel', { method:'POST', headers:getHeaders(), body:JSON.stringify({panelId:id}) });
  alert('Panel sent to Discord!');
}

async function deletePanel(id) {
  if (!confirm('Delete this panel?')) return;
  await fetch('/api/delete-panel', { method:'POST', headers:getHeaders(), body:JSON.stringify({id}) });
  loadData();
}

async function generateKey() {
  const panelId = document.getElementById('keyPanel').value;
  const durationHours = parseInt(document.getElementById('keyDuration').value) || 0;
  const note = document.getElementById('keyNote').value.trim();
  if (!panelId) return alert('Please select a panel.');
  await fetch('/api/generate-key', { method:'POST', headers:getHeaders(), body:JSON.stringify({panelId,durationHours,note}) });
  document.getElementById('keyNote').value = '';
  loadData();
}

async function deleteKey(key) {
  if (!confirm('Delete this key?')) return;
  await fetch('/api/delete-key', { method:'POST', headers:getHeaders(), body:JSON.stringify({key}) });
  loadData();
}

async function addTimeAll() {
  const hours = prompt('How many hours to add to all keys?');
  if (!hours || isNaN(hours)) return;
  await fetch('/api/add-time-all', { method:'POST', headers:getHeaders(), body:JSON.stringify({hours:parseInt(hours)}) });
  loadData();
}

async function banHwid() {
  const hwid = document.getElementById('banHwidInput').value.trim();
  if (!hwid) return alert('Enter an HWID to ban.');
  await fetch('/api/ban-hwid', { method:'POST', headers:getHeaders(), body:JSON.stringify({hwid}) });
  document.getElementById('banHwidInput').value = '';
  loadData();
}

async function unbanHwid(hwid) {
  if (!confirm('Unban this HWID?')) return;
  await fetch('/api/unban-hwid', { method:'POST', headers:getHeaders(), body:JSON.stringify({hwid}) });
  loadData();
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function logout() {
  localStorage.clear();
  window.location.href = '/logout';
}

// Handle mobile menu
if (window.innerWidth <= 768) {
  document.getElementById('menuToggle').style.display = 'inline-flex';
}

loadData();
setInterval(loadData, 30000);
</script>
</body>
</html>`);
});

// ============ LOADER ROUTES ============
app.get('/loader/:scriptId', (req, res) => {
  const { scriptId, key, hwid } = req.query;
  if (!scriptId) return res.status(400).type('text/plain').send('-- Missing script ID');
  const script = db.prepare('SELECT * FROM scripts WHERE id = ?').get(scriptId);
  if (!script) return res.status(404).type('text/plain').send('-- Script not found');
  if (script.status === 'disabled') return res.status(403).type('text/plain').send('-- Script disabled');
  if (!key) return res.status(403).type('text/plain').send('-- Missing key');
  const keyRecord = db.prepare('SELECT * FROM keys WHERE key = ? AND script_id = ?').get(key, scriptId);
  if (!keyRecord) return res.status(403).type('text/plain').send('-- Invalid key');
  if (keyRecord.expires_at && new Date(keyRecord.expires_at).getTime() < Date.now()) return res.status(403).type('text/plain').send('-- Key expired');
  if (hwid) {
    const banned = db.prepare('SELECT * FROM banned_hwids WHERE hwid = ?').get(hwid);
    if (banned) return res.status(403).type('text/plain').send('-- HWID banned');
  }
  if (hwid && !keyRecord.hwid) {
    db.prepare('UPDATE keys SET hwid = ?, last_used_at = CURRENT_TIMESTAMP WHERE key = ?').run(hwid, key);
  }
  if (hwid && keyRecord.hwid && keyRecord.hwid !== hwid) {
    return res.status(403).type('text/plain').send('-- HWID mismatch');
  }
  db.prepare('UPDATE keys SET last_used_at = CURRENT_TIMESTAMP WHERE key = ?').run(key);
  const baseUrl = publicBaseUrl();
  res.type('text/plain').send(`--[[ Karma.cc Loader ]]\nreturn (function()\n  local url = "${baseUrl}/script/${scriptId}?hwid=${hwid||''}&key=${key}"\n  local src = game:HttpGet(url)\n  if not src or #src < 10 then error("Invalid payload") end\n  local func, err = loadstring(src, "@Karma.cc")\n  if not func then error(err) end\n  return func()\nend)()`);
});

app.get('/script/:scriptId', (req, res) => {
  const script = db.prepare('SELECT * FROM scripts WHERE id = ?').get(req.params.scriptId);
  if (!script) return res.status(404).type('text/plain').send('-- Script not found');
  if (script.status === 'disabled') return res.status(403).type('text/plain').send('-- Script disabled');
  if (script.ffa_mode) {
    res.setHeader('Cache-Control', 'no-store');
    return res.type('text/plain').send(script.code || '-- Empty');
  }
  const { key, hwid } = req.query;
  if (!key) return res.status(403).type('text/plain').send('-- Missing key');
  const keyRecord = db.prepare('SELECT * FROM keys WHERE key = ? AND script_id = ?').get(key, req.params.scriptId);
  if (!keyRecord) return res.status(403).type('text/plain').send('-- Invalid key');
  if (keyRecord.expires_at && new Date(keyRecord.expires_at).getTime() < Date.now()) return res.status(403).type('text/plain').send('-- Key expired');
  if (hwid) {
    const banned = db.prepare('SELECT * FROM banned_hwids WHERE hwid = ?').get(hwid);
    if (banned) return res.status(403).type('text/plain').send('-- HWID banned');
  }
  if (hwid && keyRecord.hwid && keyRecord.hwid !== hwid) {
    return res.status(403).type('text/plain').send('-- HWID mismatch');
  }
  if (hwid && !keyRecord.hwid) {
    db.prepare('UPDATE keys SET hwid = ?, last_used_at = CURRENT_TIMESTAMP WHERE key = ?').run(hwid, key);
  }
  db.prepare('UPDATE keys SET last_used_at = CURRENT_TIMESTAMP WHERE key = ?').run(key);
  res.setHeader('Cache-Control', 'no-store');
  res.type('text/plain').send(script.code || '-- Empty');
});

// ============ DISCORD BOT ============
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds, 
    GatewayIntentBits.GuildMembers, 
    GatewayIntentBits.MessageContent, 
    GatewayIntentBits.DirectMessages,
    GatewayIntentBits.GuildMessages
  ],
  partials: [Partials.Channel, Partials.Message],
  presence: { status: PresenceUpdateStatus.Online, activities: [{ name: 'Karma.cc | /help', type: ActivityType.Watching }] }
});

client.once('ready', () => console.log(`Bot online as ${client.user.tag}`));

client.on('interactionCreate', async (interaction) => {
  if (interaction.isButton()) {
    const customId = interaction.customId;
    const parts = customId.split('_');
    const action = parts[0];
    const scriptId = parts.slice(1).join('_');
    
    try {
      // Check if user exists in database
      let user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(interaction.user.id);
      
      // If user doesn't exist, create them
      if (!user) {
        const id = `user_${crypto.randomBytes(8).toString('hex')}`;
        db.prepare(`INSERT INTO users (id, discord_id, username, avatar, provider)
                    VALUES (?, ?, ?, ?, ?)`).run(id, interaction.user.id, interaction.user.username, interaction.user.avatar || '', 'discord');
        user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(interaction.user.id);
      }
      
      // Get the script
      const script = db.prepare('SELECT * FROM scripts WHERE id = ? AND user_id = ?').get(scriptId, user.id);
      if (!script) {
        return interaction.reply({ content: '❌ Script not found or you do not own it.', ephemeral: true });
      }
      
      // Handle different button actions
      if (action === 'view') {
        const embed = new EmbedBuilder()
          .setColor(BRAND_COLOR)
          .setTitle(`📋 ${script.name}`)
          .setDescription(`Status: ${script.status === 'active' ? '✅ Active' : '❌ Disabled'}`)
          .addFields(
            { name: '📝 Version', value: script.version || '1.0.0', inline: true },
            { name: '🎯 FFA Mode', value: script.ffa_mode ? '✅ Enabled' : '❌ Disabled', inline: true },
            { name: '📦 Compressed', value: script.compress_mode ? '✅ Yes' : '❌ No', inline: true },
            { name: '📅 Created', value: new Date(script.created_at).toLocaleDateString(), inline: true },
            { name: '🔄 Updated', value: new Date(script.updated_at).toLocaleDateString(), inline: true }
          )
          .setFooter({ text: 'Karma.cc', iconURL: 'https://cdn.discordapp.com/embed/avatars/0.png' })
          .setTimestamp();
        
        // Add code preview if available
        if (script.code && script.code.length > 0) {
          const preview = script.code.length > 1000 ? script.code.substring(0, 1000) + '...' : script.code;
          embed.addFields({ name: '📄 Code Preview', value: '```lua\n' + preview + '\n```' });
        }
        
        await interaction.reply({ embeds: [embed], ephemeral: true });
        
      } else if (action === 'redeem') {
        const modal = new ModalBuilder()
          .setCustomId(`redeem_${scriptId}`)
          .setTitle('🔑 Redeem License Key');
        
        const keyInput = new TextInputBuilder()
          .setCustomId('key_input')
          .setLabel('Enter your license key')
          .setStyle(TextInputStyle.Short)
          .setPlaceholder('e.g., ABCD1234EFGH5678')
          .setRequired(true)
          .setMinLength(4)
          .setMaxLength(32);
        
        modal.addComponents(new ActionRowBuilder().addComponents(keyInput));
        await interaction.showModal(modal);
        
      } else if (action === 'loader') {
        // Get the user's key for this script
        const keyRecord = db.prepare('SELECT * FROM keys WHERE script_id = ? AND user_id = ? AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP) ORDER BY created_at DESC').get(scriptId, user.id);
        
        if (!keyRecord) {
          return interaction.reply({ 
            content: '❌ No active key found for this script. Please redeem a key first.', 
            ephemeral: true 
          });
        }
        
        const loaderCode = `loadstring(game:HttpGet("${publicBaseUrl()}/loader/${scriptId}?key=${keyRecord.key}"))()`;
        
        const embed = new EmbedBuilder()
          .setColor(BRAND_COLOR)
          .setTitle('⚡ Loader Code')
          .setDescription('Copy and paste this into your executor:')
          .addFields(
            { name: '📜 Script', value: script.name, inline: true },
            { name: '🔑 Key', value: '`' + keyRecord.key + '`', inline: true }
          )
          .setFooter({ text: 'Karma.cc', iconURL: 'https://cdn.discordapp.com/embed/avatars/0.png' })
          .setTimestamp();
        
        await interaction.reply({ 
          content: '```lua\n' + loaderCode + '\n```',
          embeds: [embed],
          ephemeral: true 
        });
        
      } else if (action === 'keys') {
        // Show all keys for this script
        const keys = db.prepare('SELECT * FROM keys WHERE script_id = ? AND user_id = ? ORDER BY created_at DESC').all(scriptId, user.id);
        
        if (!keys || keys.length === 0) {
          return interaction.reply({ 
            content: '❌ No keys found for this script.', 
            ephemeral: true 
          });
        }
        
        let keyList = '';
        for (const k of keys.slice(0, 10)) {
          const status = k.expires_at && new Date(k.expires_at).getTime() < Date.now() ? '❌ Expired' : '✅ Active';
          const hwidStatus = k.hwid ? '🔒 Locked' : '🔓 Unlocked';
          const expiry = k.expires_at ? new Date(k.expires_at).toLocaleDateString() : 'Permanent';
          keyList += `\`${k.key}\` - ${status} - ${hwidStatus} - Expires: ${expiry}\n`;
        }
        
        if (keys.length > 10) {
          keyList += `\n... and ${keys.length - 10} more keys`;
        }
        
        const embed = new EmbedBuilder()
          .setColor(BRAND_COLOR)
          .setTitle(`🔐 Keys for ${script.name}`)
          .setDescription(keyList)
          .setFooter({ text: `Total: ${keys.length} keys`, iconURL: 'https://cdn.discordapp.com/embed/avatars/0.png' })
          .setTimestamp();
        
        await interaction.reply({ embeds: [embed], ephemeral: true });
        
      } else if (action === 'resethwid') {
        // Reset HWID for a key
        const keyRecord = db.prepare('SELECT * FROM keys WHERE script_id = ? AND user_id = ? AND hwid IS NOT NULL ORDER BY created_at DESC').get(scriptId, user.id);
        
        if (!keyRecord) {
          return interaction.reply({ 
            content: '❌ No HWID-locked key found to reset.', 
            ephemeral: true 
          });
        }
        
        db.prepare('UPDATE keys SET hwid = NULL WHERE key = ?').run(keyRecord.key);
        
        await interaction.reply({ 
          content: `✅ HWID reset successfully for key \`${keyRecord.key}\``, 
          ephemeral: true 
        });
      }
      
    } catch (error) {
      console.error('Button interaction error:', error);
      await interaction.reply({ 
        content: '❌ An error occurred while processing your request.', 
        ephemeral: true 
      });
    }
  }
  
  if (interaction.isModalSubmit()) {
    if (interaction.customId.startsWith('redeem_')) {
      const scriptId = interaction.customId.split('_')[1];
      const keyVal = interaction.fields.getTextInputValue('key_input').toUpperCase().trim();
      
      try {
        // Check if user exists
        let user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(interaction.user.id);
        if (!user) {
          const id = `user_${crypto.randomBytes(8).toString('hex')}`;
          db.prepare(`INSERT INTO users (id, discord_id, username, avatar, provider)
                      VALUES (?, ?, ?, ?, ?)`).run(id, interaction.user.id, interaction.user.username, interaction.user.avatar || '', 'discord');
          user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(interaction.user.id);
        }
        
        // Find the key
        const keyRecord = db.prepare('SELECT * FROM keys WHERE key = ? AND script_id = ?').get(keyVal, scriptId);
        
        if (!keyRecord) {
          return interaction.reply({ 
            content: '❌ Invalid key. Please check and try again.', 
            ephemeral: true 
          });
        }
        
        // Check if key is expired
        if (keyRecord.expires_at && new Date(keyRecord.expires_at).getTime() < Date.now()) {
          return interaction.reply({ 
            content: '❌ This key has expired.', 
            ephemeral: true 
          });
        }
        
        // Check if key is already claimed
        if (keyRecord.claimed_by) {
          return interaction.reply({ 
            content: '❌ This key has already been claimed.', 
            ephemeral: true 
          });
        }
        
        // Claim the key
        db.prepare('UPDATE keys SET claimed_by = ?, claimed_tag = ?, last_used_at = CURRENT_TIMESTAMP WHERE key = ?')
          .run(interaction.user.id, interaction.user.tag, keyVal);
        
        await interaction.reply({ 
          content: `✅ Key \`${keyVal}\` redeemed successfully! You can now use the loader button to get your script.`, 
          ephemeral: true 
        });
        
      } catch (error) {
        console.error('Modal submit error:', error);
        await interaction.reply({ 
          content: '❌ An error occurred while redeeming your key.', 
          ephemeral: true 
        });
      }
    }
  }
});

// ============ START SERVER ============
const port = Number(process.env.PORT || 10000);
(async () => {
  app.listen(port, '0.0.0.0', () => {
    console.log(`Karma.cc running on port ${port}`);
    console.log(`Website: ${publicBaseUrl()}`);
  });
  await client.login(DISCORD_TOKEN);
})();
