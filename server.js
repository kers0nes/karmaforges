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

if (!DISCORD_TOKEN || !CLIENT_ID || !CLIENT_SECRET || !PUBLIC_BASE_URL) {
  console.error("Missing DISCORD_TOKEN, CLIENT_ID, CLIENT_SECRET, or PUBLIC_BASE_URL.");
  process.exit(1);
}

console.log('Karma.cc starting...');

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

function publicBaseUrl() { return PUBLIC_BASE_URL.replace(/\/$/, ''); }
function escapeHtml(s) { return String(s).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#039;'); }
function getSessionUser(req) { return req.session.user || null; }
function requireAuth(req, res, next) { if (req.session.user) return next(); res.redirect('/'); }

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
  res.json({ scripts, panels, keys, bannedHWIDs: banned, serverTime: Date.now() });
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
  const expiresAt = durationHours > 0 ? new Date(Date.now() + durationHours * 3600000).toISOString() : null;
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

// ============ DISCORD OAUTH (NO /api PREFIX) ============
app.get('/auth/discord', (req, res) => {
  const state = crypto.randomBytes(18).toString('hex');
  req.session.oauth_state = state;
  req.session.save((err) => {
    if (err) console.error('Session save error:', err);
    const redirectUri = `${publicBaseUrl()}/auth/discord/callback`;
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

app.get('/auth/discord/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code || !state) return res.status(400).send('Missing code or state');
  
  if (state !== req.session.oauth_state) {
    console.warn(`OAuth state mismatch: received ${state}, expected ${req.session.oauth_state}`);
    return res.status(403).send('Invalid state parameter');
  }
  
  try {
    const redirectUri = `${publicBaseUrl()}/auth/discord/callback`;
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
      global_name: user.global_name || user.username,
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

// ============ LOGIN PAGE ============
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Karma.cc</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
      background: #0a0a0a;
      color: #fff;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .login-container {
      background: #141414;
      border: 1px solid #2a2a2a;
      border-radius: 16px;
      padding: 48px 40px;
      max-width: 400px;
      width: 100%;
      text-align: center;
    }
    .logo { font-size: 32px; font-weight: 800; margin-bottom: 8px; }
    .logo span { color: #FFD700; }
    .sub { color: #888; font-size: 14px; margin-bottom: 30px; }
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      width: 100%;
      padding: 14px 24px;
      border: none;
      border-radius: 10px;
      font-weight: 600;
      font-size: 15px;
      cursor: pointer;
      transition: all 0.2s;
      text-decoration: none;
    }
    .btn-discord { background: #5865F2; color: white; }
    .btn-discord:hover { background: #4752C4; transform: translateY(-2px); }
    .btn-gold { background: #FFD700; color: #0a0a08; }
    .btn-gold:hover { transform: translateY(-2px); opacity: 0.9; }
    .btn-outline { background: transparent; border: 1px solid #2a2a2a; color: #fff; }
    .btn-outline:hover { border-color: #FFD700; color: #FFD700; }
    .input {
      width: 100%;
      background: #1a1a1a;
      border: 1px solid #2a2a2a;
      color: #fff;
      padding: 12px 16px;
      border-radius: 10px;
      font-size: 14px;
      margin-bottom: 12px;
    }
    .input:focus { outline: none; border-color: #FFD700; }
    .divider { display: flex; align-items: center; gap: 12px; color: #555; font-size: 13px; margin: 16px 0; }
    .divider::before, .divider::after { content: ''; flex: 1; height: 1px; background: #2a2a2a; }
    .hidden { display: none; }
    .tab-btn {
      background: none;
      border: none;
      color: #888;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      padding: 8px 20px;
      border-radius: 8px;
      transition: all 0.2s;
    }
    .tab-btn.active { color: #FFD700; background: rgba(255,215,0,0.1); }
    .tab-btn:hover { color: #fff; }
    .flex-col { display: flex; flex-direction: column; gap: 10px; }
    .mt-16 { margin-top: 16px; }
  </style>
</head>
<body>
<div class="login-container">
  <div class="logo">Karma<span>.cc</span></div>
  <p class="sub">Premium script protection with HWID-locked keys</p>
  
  <div style="display:flex;justify-content:center;gap:4px;margin-bottom:20px;">
    <button class="tab-btn active" onclick="switchTab('login')">Login</button>
    <button class="tab-btn" onclick="switchTab('register')">Register</button>
  </div>
  
  <div id="tab-login" class="flex-col">
    <input class="input" id="login-email" placeholder="Email" type="email">
    <input class="input" id="login-password" placeholder="Password" type="password">
    <button class="btn btn-gold" onclick="emailLogin()">Sign In</button>
    <div class="divider">or continue with</div>
    <a href="/auth/discord" class="btn btn-discord">
      <svg width="20" height="20" viewBox="0 0 127.14 96.36" fill="white"><path d="M107.7,8.07A105.15,105.15,0,0,0,81.47,0a72.06,72.06,0,0,0-3.36,6.83A97.68,97.68,0,0,0,49,6.83,72.37,72.37,0,0,0,45.64,0,105.89,105.89,0,0,0,19.39,8.09C2.79,32.65-1.71,56.6.54,80.21h0A105.73,105.73,0,0,0,32.71,96.36,77.7,77.7,0,0,0,39.6,85.25a68.42,68.42,0,0,1-10.85-5.18c.91-.66,1.8-1.34,2.66-2a75.57,75.57,0,0,0,64.32,0c.87.71,1.76,1.39,2.66,2a68.68,68.68,0,0,1-10.87,5.19,77,77,0,0,0,6.89,11.1A105.25,105.25,0,0,0,126.6,80.22h0C129.24,52.84,122.09,29.11,107.7,8.07ZM42.45,65.69C36.18,65.69,31,60,31,53s5-12.74,11.43-12.74S54,46,53.89,53,48.84,65.69,42.45,65.69Zm42.24,0C78.41,65.69,73.31,60,73.31,53s5-12.74,11.43-12.74S96.1,46,96,53,91.08,65.69,84.69,65.69Z"/></svg>
      Login with Discord
    </a>
  </div>
  
  <div id="tab-register" class="flex-col hidden">
    <input class="input" id="register-username" placeholder="Username">
    <input class="input" id="register-email" placeholder="Email" type="email">
    <input class="input" id="register-password" placeholder="Password" type="password">
    <button class="btn btn-gold" onclick="emailRegister()">Create Account</button>
    <div class="divider">or</div>
    <a href="/auth/discord" class="btn btn-discord">
      <svg width="20" height="20" viewBox="0 0 127.14 96.36" fill="white"><path d="M107.7,8.07A105.15,105.15,0,0,0,81.47,0a72.06,72.06,0,0,0-3.36,6.83A97.68,97.68,0,0,0,49,6.83,72.37,72.37,0,0,0,45.64,0,105.89,105.89,0,0,0,19.39,8.09C2.79,32.65-1.71,56.6.54,80.21h0A105.73,105.73,0,0,0,32.71,96.36,77.7,77.7,0,0,0,39.6,85.25a68.42,68.42,0,0,1-10.85-5.18c.91-.66,1.8-1.34,2.66-2a75.57,75.57,0,0,0,64.32,0c.87.71,1.76,1.39,2.66,2a68.68,68.68,0,0,1-10.87,5.19,77,77,0,0,0,6.89,11.1A105.25,105.25,0,0,0,126.6,80.22h0C129.24,52.84,122.09,29.11,107.7,8.07ZM42.45,65.69C36.18,65.69,31,60,31,53s5-12.74,11.43-12.74S54,46,53.89,53,48.84,65.69,42.45,65.69Zm42.24,0C78.41,65.69,73.31,60,73.31,53s5-12.74,11.43-12.74S96.1,46,96,53,91.08,65.69,84.69,65.69Z"/></svg>
      Continue with Discord
    </a>
  </div>
</div>

<script>
function switchTab(tab) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-login').classList.toggle('hidden', tab !== 'login');
  document.getElementById('tab-register').classList.toggle('hidden', tab !== 'register');
  document.querySelector('.tab-btn[onclick*="' + tab + '"]').classList.add('active');
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
</script>
</body>
</html>`);
});

// ============ DASHBOARD ============
app.get('/dashboard', requireAuth, (req, res) => {
  const user = req.session.user;
  const escapedUsername = escapeHtml(user.global_name || user.username || user.email || 'User');
  const avatarUrl = user.avatar ? `https://cdn.discordapp.com/avatars/${user.discord_id}/${user.avatar}.png?size=128` : 'https://cdn.discordapp.com/embed/avatars/0.png';
  const botInviteUrl = `https://discord.com/oauth2/authorize?client_id=${CLIENT_ID}&permissions=8&scope=bot`;
  
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>Karma.cc</title>
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
      background: #0a0a0a;
      color: #e5e5e5;
      min-height: 100vh;
    }
    .app { display: flex; height: 100vh; overflow: hidden; }
    .sidebar {
      width: 240px;
      background: #0d0d0d;
      border-right: 1px solid #1a1a1a;
      padding: 24px 16px;
      display: flex;
      flex-direction: column;
      flex-shrink: 0;
      height: 100vh;
      overflow-y: auto;
    }
    .sidebar::-webkit-scrollbar { width: 4px; }
    .sidebar::-webkit-scrollbar-thumb { background: #2a2a2a; border-radius: 4px; }
    .sidebar-brand {
      font-size: 22px;
      font-weight: 800;
      color: #fff;
      padding: 0 8px 24px 8px;
      border-bottom: 1px solid #1a1a1a;
      margin-bottom: 16px;
    }
    .sidebar-brand span { color: #FFD700; }
    .sidebar-nav { flex: 1; }
    .sidebar-nav .nav-item {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 10px 12px;
      border-radius: 8px;
      color: #888;
      font-size: 14px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s;
      text-decoration: none;
      margin-bottom: 2px;
    }
    .sidebar-nav .nav-item:hover { background: #1a1a1a; color: #fff; }
    .sidebar-nav .nav-item.active { background: rgba(255,215,0,0.08); color: #FFD700; }
    .sidebar-nav .nav-item .icon { width: 20px; text-align: center; font-size: 16px; }
    .sidebar-nav .nav-label {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #444;
      padding: 12px 12px 6px;
      font-weight: 700;
    }
    .sidebar-footer {
      border-top: 1px solid #1a1a1a;
      padding-top: 12px;
      margin-top: 8px;
    }
    .sidebar-footer .user-row {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 8px 12px;
      border-radius: 8px;
    }
    .sidebar-footer .user-row .avatar {
      width: 32px;
      height: 32px;
      border-radius: 50%;
      object-fit: cover;
      border: 1px solid #2a2a2a;
    }
    .sidebar-footer .user-row .name {
      font-size: 13px;
      font-weight: 600;
      color: #e5e5e5;
    }
    .sidebar-footer .user-row .tag {
      font-size: 11px;
      color: #666;
    }
    .sidebar-footer .logout-btn {
      display: block;
      width: 100%;
      padding: 8px 12px;
      margin-top: 8px;
      border: none;
      background: transparent;
      color: #666;
      font-size: 13px;
      font-weight: 500;
      text-align: left;
      cursor: pointer;
      border-radius: 8px;
      transition: all 0.15s;
    }
    .sidebar-footer .logout-btn:hover { background: #1a1a1a; color: #ef4444; }
    .main {
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
      padding: 16px 30px;
      background: #0d0d0d;
      border-bottom: 1px solid #1a1a1a;
    }
    .topbar .page-title { font-size: 20px; font-weight: 700; }
    .topbar .page-title span { color: #FFD700; }
    .topbar .right { display: flex; align-items: center; gap: 16px; }
    .topbar .right .mobile-toggle {
      display: none;
      background: none;
      border: none;
      color: #888;
      font-size: 24px;
      cursor: pointer;
      padding: 4px 8px;
    }
    .content {
      flex: 1;
      overflow-y: auto;
      padding: 24px 30px;
    }
    .content::-webkit-scrollbar { width: 6px; }
    .content::-webkit-scrollbar-thumb { background: #2a2a2a; border-radius: 4px; }
    .card {
      background: #111;
      border: 1px solid #1a1a1a;
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
    }
    .card h2 { font-size: 18px; font-weight: 700; margin-bottom: 16px; }
    .card h2 span { color: #FFD700; }
    .input, textarea, select {
      width: 100%;
      background: #1a1a1a;
      border: 1px solid #2a2a2a;
      color: #e5e5e5;
      padding: 10px 14px;
      border-radius: 8px;
      font-size: 14px;
      margin-bottom: 12px;
      transition: all 0.2s;
    }
    .input:focus, textarea:focus, select:focus {
      outline: none;
      border-color: #FFD700;
    }
    textarea { min-height: 100px; font-family: 'Courier New', monospace; resize: vertical; }
    select { appearance: none; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%23888' d='M6 8L1 3h10z'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 12px center; background-size: 12px; }
    .btn {
      padding: 10px 20px;
      border: none;
      border-radius: 8px;
      font-weight: 600;
      font-size: 13px;
      cursor: pointer;
      transition: all 0.2s;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .btn-gold { background: #FFD700; color: #0a0a08; }
    .btn-gold:hover { opacity: 0.85; transform: translateY(-1px); }
    .btn-danger { background: rgba(239,68,68,0.15); color: #ef4444; border: 1px solid rgba(239,68,68,0.2); }
    .btn-danger:hover { background: rgba(239,68,68,0.25); }
    .btn-success { background: rgba(16,185,129,0.15); color: #10b981; border: 1px solid rgba(16,185,129,0.2); }
    .btn-success:hover { background: rgba(16,185,129,0.25); }
    .btn-outline { background: transparent; border: 1px solid #2a2a2a; color: #e5e5e5; }
    .btn-outline:hover { border-color: #FFD700; color: #FFD700; }
    .flex { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    .view-section { display: none; }
    .view-section.active { display: block; animation: fadeIn 0.2s ease; }
    @keyframes fadeIn { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:translateY(0); } }
    .scripts-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
      gap: 16px;
    }
    .script-card {
      background: #0d0d0d;
      border: 1px solid #1a1a1a;
      border-radius: 10px;
      padding: 16px;
      transition: all 0.2s;
    }
    .script-card:hover { border-color: #FFD700; transform: translateY(-2px); }
    .script-card .title { font-weight: 600; font-size: 15px; margin-bottom: 6px; }
    .script-card .meta { font-size: 12px; color: #666; margin-bottom: 10px; }
    .script-card .actions { display: flex; gap: 6px; flex-wrap: wrap; }
    .script-card .actions .btn { flex: 1; padding: 6px 10px; font-size: 12px; justify-content: center; }
    .badge {
      display: inline-block;
      padding: 2px 10px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
    }
    .badge-green { background: rgba(16,185,129,0.15); color: #10b981; }
    .badge-red { background: rgba(239,68,68,0.15); color: #ef4444; }
    .badge-yellow { background: rgba(255,215,0,0.15); color: #FFD700; }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 12px;
      margin-top: 16px;
    }
    .stat-card {
      background: #0d0d0d;
      border: 1px solid #1a1a1a;
      border-radius: 10px;
      padding: 16px;
      text-align: center;
    }
    .stat-card .num { font-size: 28px; font-weight: 900; color: #FFD700; }
    .stat-card .label { font-size: 12px; color: #666; margin-top: 4px; }
    .text-muted { color: #666; }
    .mt-8 { margin-top: 8px; }
    .mt-16 { margin-top: 16px; }
    @media (max-width: 768px) {
      .sidebar { display: none; position: fixed; top: 0; left: 0; width: 260px; height: 100vh; z-index: 1000; background: #0a0a0a; }
      .sidebar.open { display: flex; }
      .topbar .right .mobile-toggle { display: block; }
      .main { width: 100%; }
      .topbar { padding: 12px 16px; }
      .content { padding: 16px; }
      .grid-2 { grid-template-columns: 1fr; }
      .scripts-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
<div class="app">
  <div class="sidebar" id="sidebar">
    <div class="sidebar-brand">Karma<span>.cc</span></div>
    <div class="sidebar-nav">
      <div class="nav-label">Navigation</div>
      <div class="nav-item active" onclick="switchView('overview', this)"><span class="icon">📊</span> Overview</div>
      <div class="nav-item" onclick="switchView('scripts', this)"><span class="icon">📜</span> Scripts</div>
      <div class="nav-item" onclick="switchView('panels', this)"><span class="icon">📋</span> Panels</div>
      <div class="nav-item" onclick="switchView('keys', this)"><span class="icon">🔑</span> Keys</div>
      <div class="nav-item" onclick="switchView('hwids', this)"><span class="icon">🚫</span> HWID Bans</div>
      <div class="nav-label mt-16">Legal</div>
      <div class="nav-item" onclick="alert('Terms & Privacy')"><span class="icon">⚖️</span> Terms & Privacy</div>
    </div>
    <div class="sidebar-footer">
      <div class="user-row">
        <img class="avatar" src="${avatarUrl}" alt="Avatar">
        <div><div class="name">${escapedUsername}</div><div class="tag">${user.discord_id ? 'Discord' : 'Email'}</div></div>
      </div>
      <button class="logout-btn" onclick="logout()">🚪 Log out</button>
    </div>
  </div>
  
  <div class="main">
    <div class="topbar">
      <div class="page-title"><span id="pageTitle">Overview</span></div>
      <div class="right"><button class="mobile-toggle" onclick="toggleSidebar()">☰</button></div>
    </div>
    
    <div class="content">
      <div id="view-overview" class="view-section active">
        <div class="card">
          <h2>Welcome, <span>${escapedUsername}</span></h2>
          <p class="text-muted">Manage your scripts, panels, and keys from one place.</p>
          <div class="stats-grid" id="statsGrid">
            <div class="stat-card"><div class="num" id="statScripts">0</div><div class="label">Scripts</div></div>
            <div class="stat-card"><div class="num" id="statPanels">0</div><div class="label">Panels</div></div>
            <div class="stat-card"><div class="num" id="statKeys">0</div><div class="label">Keys</div></div>
            <div class="stat-card"><div class="num" id="statBanned">0</div><div class="label">Banned HWIDs</div></div>
          </div>
        </div>
        <div class="card">
          <h3>🤖 Invite Bot</h3>
          <p class="text-muted">Add Karma.cc bot to your Discord server.</p>
          <a href="${botInviteUrl}" target="_blank" class="btn btn-gold mt-8">Invite Bot</a>
        </div>
      </div>
      
      <div id="view-scripts" class="view-section">
        <div class="card">
          <h2>Your <span>Scripts</span></h2>
          <div class="flex" style="margin-bottom:10px;">
            <input type="text" id="scriptName" placeholder="Script name" style="flex:1;min-width:120px;margin:0;">
            <label style="display:flex;align-items:center;gap:6px;padding:8px 12px;background:#1a1a1a;border:1px solid #2a2a2a;border-radius:8px;cursor:pointer;font-size:13px;">
              <input type="checkbox" id="compressMode"> Compress
            </label>
            <button class="btn btn-gold" onclick="createScript()">+ Create</button>
          </div>
          <textarea id="scriptCode" rows="6" placeholder="Paste your Lua code here..."></textarea>
        </div>
        <div id="scriptsList" class="scripts-grid"></div>
      </div>
      
      <div id="view-panels" class="view-section">
        <div class="card">
          <h2>Discord <span>Panels</span></h2>
          <div class="grid-2">
            <input type="text" id="panelName" placeholder="Panel name">
            <input type="text" id="panelChannel" placeholder="Discord Channel ID">
          </div>
          <textarea id="panelDesc" rows="2" placeholder="Panel description..."></textarea>
          <select id="panelScript"><option value="">Select script...</option></select>
          <input type="number" id="panelCooldown" placeholder="HWID cooldown (seconds)" value="180">
          <button class="btn btn-gold" onclick="createPanel()">+ Create Panel</button>
        </div>
        <div id="panelsList" class="scripts-grid"></div>
      </div>
      
      <div id="view-keys" class="view-section">
        <div class="card">
          <h2>Generate <span>Keys</span></h2>
          <select id="keyPanel"><option value="">Select panel...</option></select>
          <input type="number" id="keyDuration" placeholder="Duration (hours, 0 = permanent)" value="0">
          <input type="text" id="keyNote" placeholder="Note (optional)">
          <button class="btn btn-gold" onclick="generateKey()">Generate Key</button>
        </div>
        <div id="keysList" class="scripts-grid"></div>
      </div>
      
      <div id="view-hwids" class="view-section">
        <div class="card">
          <h2>Ban <span>HWID</span></h2>
          <div class="flex">
            <input type="text" id="banHwidInput" placeholder="Enter HWID to ban" style="flex:1;margin:0;">
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
  document.getElementById('statScripts').textContent = currentData.scripts.length;
  document.getElementById('statPanels').textContent = currentData.panels.length;
  document.getElementById('statKeys').textContent = currentData.keys.length;
  document.getElementById('statBanned').textContent = currentData.bannedHWIDs.length;
  renderScripts();
  renderPanels();
  renderKeys();
  renderHwids();
  updateSelects();
}

function renderScripts() {
  const container = document.getElementById('scriptsList');
  if (!currentData.scripts.length) {
    container.innerHTML = '<div style="grid-column:1/-1;padding:30px;text-align:center;color:#666;background:#0d0d0d;border-radius:10px;border:1px dashed #1a1a1a;">No scripts yet. Create one above.</div>';
    return;
  }
  let html = '';
  for (const s of currentData.scripts) {
    const statusClass = s.status === 'active' ? 'badge-green' : 'badge-red';
    const statusText = s.status === 'active' ? 'Active' : 'Disabled';
    const ffaBadge = s.ffa_mode ? '<span class="badge badge-yellow">FFA</span>' : '';
    html += '<div class="script-card">' +
      '<div class="title">' + escapeHtml(s.name) + '</div>' +
      '<div class="meta"><span class="badge ' + statusClass + '">' + statusText + '</span> ' + ffaBadge + ' <span style="margin-left:8px;">' + new Date(s.created_at).toLocaleDateString() + '</span></div>' +
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
    container.innerHTML = '<div style="grid-column:1/-1;padding:30px;text-align:center;color:#666;background:#0d0d0d;border-radius:10px;border:1px dashed #1a1a1a;">No panels yet. Create one above.</div>';
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
    container.innerHTML = '<div style="grid-column:1/-1;padding:30px;text-align:center;color:#666;background:#0d0d0d;border-radius:10px;border:1px dashed #1a1a1a;">No keys generated yet.</div>';
    return;
  }
  let html = '';
  for (const k of currentData.keys) {
    const expired = k.expires_at && new Date(k.expires_at).getTime() < serverTime;
    let status = 'Active', badge = 'badge-green';
    if (expired) { status = 'Expired'; badge = 'badge-red'; }
    else if (k.hwid) { status = 'HWID Locked'; badge = 'badge-yellow'; }
    html += '<div class="script-card">' +
      '<div class="title" style="font-family:monospace;font-size:13px;color:#FFD700;">' + escapeHtml(k.key) + '</div>' +
      '<div class="meta"><span class="badge ' + badge + '">' + status + '</span> ' + (k.note ? '<span style="margin-left:8px;">'+escapeHtml(k.note)+'</span>' : '') + '</div>' +
      '<div class="actions"><button class="btn btn-danger" onclick="deleteKey(\'' + k.key + '\')">Delete</button></div></div>';
  }
  container.innerHTML = html;
}

function renderHwids() {
  const container = document.getElementById('hwidsList');
  if (!currentData.bannedHWIDs.length) {
    container.innerHTML = '<div style="grid-column:1/-1;padding:30px;text-align:center;color:#666;background:#0d0d0d;border-radius:10px;border:1px dashed #1a1a1a;">No banned HWIDs.</div>';
    return;
  }
  let html = '';
  for (const h of currentData.bannedHWIDs) {
    html += '<div class="script-card">' +
      '<div class="title" style="font-family:monospace;font-size:13px;color:#ef4444;">' + escapeHtml(h.hwid) + '</div>' +
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
  document.getElementById('pageTitle').textContent = view.charAt(0).toUpperCase() + view.slice(1);
  if (window.innerWidth <= 768) document.getElementById('sidebar').classList.remove('open');
}

function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

async function createScript() {
  const name = document.getElementById('scriptName').value.trim();
  const code = document.getElementById('scriptCode').value;
  const compressMode = document.getElementById('compressMode').checked;
  if (!name || !code) return alert('Please enter a name and code.');
  await fetch('/api/create-script', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name,code,compressMode}) });
  document.getElementById('scriptName').value = '';
  document.getElementById('scriptCode').value = '';
  document.getElementById('compressMode').checked = false;
  loadData();
}

async function toggleScript(id) {
  await fetch('/api/scripts/'+id+'/toggle', { method:'PUT', headers:{'Content-Type':'application/json'} });
  loadData();
}

async function toggleFfa(id) {
  await fetch('/api/scripts/'+id+'/ffa', { method:'PUT', headers:{'Content-Type':'application/json'} });
  loadData();
}

async function deleteScript(id) {
  if (!confirm('Delete this script?')) return;
  await fetch('/api/delete-script', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id}) });
  loadData();
}

async function createPanel() {
  const name = document.getElementById('panelName').value.trim();
  const description = document.getElementById('panelDesc').value;
  const channelId = document.getElementById('panelChannel').value.trim();
  const scriptId = document.getElementById('panelScript').value;
  const hwidCooldown = parseInt(document.getElementById('panelCooldown').value) || 180;
  if (!name || !channelId || !scriptId) return alert('Please fill in all required fields.');
  await fetch('/api/create-panel', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name,description,channelId,scriptId,hwidCooldown}) });
  document.getElementById('panelName').value = '';
  document.getElementById('panelDesc').value = '';
  document.getElementById('panelChannel').value = '';
  document.getElementById('panelCooldown').value = '180';
  loadData();
}

async function sendPanel(id) {
  await fetch('/api/send-panel', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({panelId:id}) });
  alert('Panel sent to Discord!');
}

async function deletePanel(id) {
  if (!confirm('Delete this panel?')) return;
  await fetch('/api/delete-panel', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id}) });
  loadData();
}

async function generateKey() {
  const panelId = document.getElementById('keyPanel').value;
  const durationHours = parseInt(document.getElementById('keyDuration').value) || 0;
  const note = document.getElementById('keyNote').value.trim();
  if (!panelId) return alert('Please select a panel.');
  await fetch('/api/generate-key', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({panelId,durationHours,note}) });
  document.getElementById('keyNote').value = '';
  loadData();
}

async function deleteKey(key) {
  if (!confirm('Delete this key?')) return;
  await fetch('/api/delete-key', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({key}) });
  loadData();
}

async function banHwid() {
  const hwid = document.getElementById('banHwidInput').value.trim();
  if (!hwid) return alert('Enter an HWID to ban.');
  await fetch('/api/ban-hwid', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({hwid}) });
  document.getElementById('banHwidInput').value = '';
  loadData();
}

async function unbanHwid(hwid) {
  if (!confirm('Unban this HWID?')) return;
  await fetch('/api/unban-hwid', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({hwid}) });
  loadData();
}

function logout() {
  localStorage.clear();
  window.location.href = '/logout';
}

document.addEventListener('click', function(e) {
  const sidebar = document.getElementById('sidebar');
  const toggle = document.querySelector('.mobile-toggle');
  if (window.innerWidth <= 768 && sidebar.classList.contains('open')) {
    if (!sidebar.contains(e.target) && !toggle.contains(e.target)) {
      sidebar.classList.remove('open');
    }
  }
});

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
  
  if (script.ffa_mode) {
    return res.type('text/plain').send(`loadstring(game:HttpGet("${publicBaseUrl()}/script/${scriptId}"))()`);
  }
  
  if (!key) return res.status(403).type('text/plain').send('-- Missing key');
  
  const keyRecord = db.prepare('SELECT * FROM keys WHERE key = ? AND script_id = ?').get(key, scriptId);
  if (!keyRecord) return res.status(403).type('text/plain').send('-- Invalid key');
  if (keyRecord.expires_at && new Date(keyRecord.expires_at).getTime() < Date.now()) {
    return res.status(403).type('text/plain').send('-- Key expired');
  }
  
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
  res.type('text/plain').send(`loadstring(game:HttpGet("${publicBaseUrl()}/script/${scriptId}?key=${key}"))()`);
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
  if (keyRecord.expires_at && new Date(keyRecord.expires_at).getTime() < Date.now()) {
    return res.status(403).type('text/plain').send('-- Key expired');
  }
  
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
  if (!interaction.isButton() && !interaction.isModalSubmit()) return;
  
  try {
    let user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(interaction.user.id);
    if (!user) {
      const id = `user_${crypto.randomBytes(8).toString('hex')}`;
      db.prepare(`INSERT INTO users (id, discord_id, username, avatar, provider)
                  VALUES (?, ?, ?, ?, ?)`).run(id, interaction.user.id, interaction.user.username, interaction.user.avatar || '', 'discord');
      user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(interaction.user.id);
    }
    
    if (interaction.isButton()) {
      const parts = interaction.customId.split('_');
      const action = parts[0];
      const scriptId = parts.slice(1).join('_');
      
      const script = db.prepare('SELECT * FROM scripts WHERE id = ? AND user_id = ?').get(scriptId, user.id);
      if (!script) {
        return interaction.reply({ content: '❌ Script not found.', ephemeral: true });
      }
      
      if (action === 'view') {
        const embed = new EmbedBuilder()
          .setColor(BRAND_COLOR)
          .setTitle(`📋 ${script.name}`)
          .setDescription(`Status: ${script.status === 'active' ? '✅ Active' : '❌ Disabled'}`)
          .addFields(
            { name: 'Version', value: script.version || '1.0.0', inline: true },
            { name: 'FFA Mode', value: script.ffa_mode ? '✅ Enabled' : '❌ Disabled', inline: true },
            { name: 'Compressed', value: script.compress_mode ? '✅ Yes' : '❌ No', inline: true }
          )
          .setFooter({ text: 'Karma.cc' })
          .setTimestamp();
        await interaction.reply({ embeds: [embed], ephemeral: true });
      } else if (action === 'redeem') {
        const modal = new ModalBuilder()
          .setCustomId(`redeem_${scriptId}`)
          .setTitle('Redeem Key');
        modal.addComponents(
          new ActionRowBuilder().addComponents(
            new TextInputBuilder()
              .setCustomId('key_input')
              .setLabel('Enter your license key')
              .setStyle(TextInputStyle.Short)
              .setRequired(true)
          )
        );
        await interaction.showModal(modal);
      } else if (action === 'loader') {
        const keyRecord = db.prepare('SELECT * FROM keys WHERE script_id = ? AND user_id = ? AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP) ORDER BY created_at DESC').get(scriptId, user.id);
        if (!keyRecord) {
          return interaction.reply({ content: '❌ No active key found.', ephemeral: true });
        }
        const loader = `loadstring(game:HttpGet("${publicBaseUrl()}/loader/${scriptId}?key=${keyRecord.key}"))()`;
        await interaction.reply({ content: `\`\`\`lua\n${loader}\n\`\`\``, ephemeral: true });
      } else if (action === 'keys') {
        const keys = db.prepare('SELECT * FROM keys WHERE script_id = ? AND user_id = ? ORDER BY created_at DESC').all(scriptId, user.id);
        if (!keys || keys.length === 0) {
          return interaction.reply({ content: '❌ No keys found.', ephemeral: true });
        }
        let keyList = keys.slice(0, 10).map(k => {
          const status = k.expires_at && new Date(k.expires_at).getTime() < Date.now() ? '❌' : '✅';
          return `\`${k.key}\` ${status}`;
        }).join('\n');
        if (keys.length > 10) keyList += `\n... and ${keys.length - 10} more`;
        await interaction.reply({ content: `**Keys for ${script.name}**\n${keyList}`, ephemeral: true });
      } else if (action === 'resethwid') {
        const keyRecord = db.prepare('SELECT * FROM keys WHERE script_id = ? AND user_id = ? AND hwid IS NOT NULL ORDER BY created_at DESC').get(scriptId, user.id);
        if (!keyRecord) {
          return interaction.reply({ content: '❌ No HWID-locked key found.', ephemeral: true });
        }
        db.prepare('UPDATE keys SET hwid = NULL WHERE key = ?').run(keyRecord.key);
        await interaction.reply({ content: `✅ HWID reset for \`${keyRecord.key}\``, ephemeral: true });
      }
    }
    
    if (interaction.isModalSubmit() && interaction.customId.startsWith('redeem_')) {
      const scriptId = interaction.customId.split('_')[1];
      const keyVal = interaction.fields.getTextInputValue('key_input').toUpperCase().trim();
      
      const keyRecord = db.prepare('SELECT * FROM keys WHERE key = ? AND script_id = ?').get(keyVal, scriptId);
      if (!keyRecord) return interaction.reply({ content: '❌ Invalid key.', ephemeral: true });
      if (keyRecord.expires_at && new Date(keyRecord.expires_at).getTime() < Date.now()) {
        return interaction.reply({ content: '❌ Key expired.', ephemeral: true });
      }
      if (keyRecord.claimed_by) {
        return interaction.reply({ content: '❌ Key already claimed.', ephemeral: true });
      }
      
      db.prepare('UPDATE keys SET claimed_by = ?, claimed_tag = ?, last_used_at = CURRENT_TIMESTAMP WHERE key = ?')
        .run(interaction.user.id, interaction.user.tag, keyVal);
      await interaction.reply({ content: `✅ Key \`${keyVal}\` redeemed!`, ephemeral: true });
    }
  } catch (error) {
    console.error('Interaction error:', error);
    await interaction.reply({ content: '❌ An error occurred.', ephemeral: true }).catch(() => {});
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
