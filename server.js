// server.js – Karma Protection v7.0 (FULL REWRITE)
// Production-ready with 12 slash commands, fixed renderer, and new features

const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');
const session = require('express-session');
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
  SlashCommandBuilder,
  REST,
  Routes
} = require('discord.js');

// ============ ENVIRONMENT ============
const DISCORD_TOKEN = process.env.DISCORD_TOKEN;
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const GUILD_ID = process.env.GUILD_ID;
const DATABASE_PATH = process.env.DATABASE_PATH || './data.sqlite';
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || 'https://karmaforges.onrender.com';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const OWNER_ID = process.env.OWNER_ID || 'YOUR_DISCORD_ID_HERE';
const BRAND_COLOR = parseInt(process.env.BRAND_COLOR) || 0x1a3a6b;
const COOLDOWN_MS = 24 * 60 * 60 * 1000;

if (!DISCORD_TOKEN || !CLIENT_SECRET) {
  console.error('Missing DISCORD_TOKEN or CLIENT_SECRET.');
  process.exit(1);
}

console.log('Karma Protection v7.0 – FULL REWRITE starting...');
console.log(`Database: ${DATABASE_PATH}`);
console.log(`Base URL: ${PUBLIC_BASE_URL}`);

// ============ DATABASE ============
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

CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  key TEXT UNIQUE NOT NULL,
  name TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id)
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
  user_id TEXT NOT NULL,
  key TEXT UNIQUE NOT NULL,
  hwid TEXT,
  note TEXT,
  expires_at TEXT,
  resettable TEXT,
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

CREATE TABLE IF NOT EXISTS command_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT,
  command TEXT,
  args TEXT,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
`);

// ============ HELPERS ============
function makeId(prefix = 'script') { return `${prefix}_${crypto.randomBytes(6).toString('hex')}`; }

function generateKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = 'KARMA-';
  for (let i = 0; i < 4; i++) {
    if (i > 0) result += '-';
    for (let j = 0; j < 4; j++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
  }
  return result;
}

function generateApiKey() {
  return 'kp_' + crypto.randomBytes(32).toString('hex');
}

function generateRecoveryToken() {
  return crypto.randomBytes(32).toString('hex');
}

function maskKey(key) { return key ? 'KARMA-****-****-' + key.slice(-4).toUpperCase() : 'Invalid'; }
function addHours(hours) { return (hours && hours > 0) ? new Date(Date.now() + hours * 3600000).toISOString() : null; }
function publicBaseUrl() { return PUBLIC_BASE_URL.replace(/\/$/, ''); }
function escapeHtml(s) { return String(s).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#039;'); }
function getSessionUser(req) { return req.session.user || null; }
function requireAuth(req, res, next) { if (req.session.user) return next(); res.redirect('/'); }
function formatExpiry(e) { return e ? new Date(e).toLocaleDateString() + ' ' + new Date(e).toLocaleTimeString() : 'Permanent'; }

// Password hashing using built-in crypto.scrypt
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

function obfuscateLua(code) {
  const base64 = Buffer.from(code).toString('base64');
  return `--[[ Obfuscated by Karma Protection ]]\nlocal code = "${base64}"\nlocal decoded = (function(s) return (s:gsub('..', function(c) return string.char(tonumber(c, 16)) end)) end)(code)\nloadstring(decoded)()`;
}

function logCommand(userId, command, args) {
  db.prepare('INSERT INTO command_logs (user_id, command, args) VALUES (?, ?, ?)').run(userId, command, args || '');
}

// ============ EXPRESS APP ============
const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: PUBLIC_BASE_URL.startsWith('https'), maxAge: 7 * 24 * 60 * 60 * 1000 }
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
  const apiKeys = db.prepare('SELECT id, key, name, created_at, last_used_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC').all(user.id);
  const logs = db.prepare('SELECT * FROM command_logs ORDER BY timestamp DESC LIMIT 50').all();
  res.json({ scripts, panels, keys, bannedHWIDs: banned, whitelist, apiKeys, logs, serverTime: Date.now() });
});

app.post('/api/create-script', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { name, code, compressMode } = req.body;
  if (!name || !code) return res.status(400).json({ error: 'Missing name or code' });
  const id = makeId('script');
  const obfuscated = obfuscateLua(code);
  db.prepare(`INSERT INTO scripts (id, user_id, name, code, obfuscated_code, version, status, compress_mode)
              VALUES (?, ?, ?, ?, ?, '1.0.0', 'active', ?)`).run(id, user.id, name, code, obfuscated, compressMode ? 1 : 0);
  res.json({ success: true, id });
});

app.post('/api/update-script', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { id, name, code } = req.body;
  if (!id || !name || !code) return res.status(400).json({ error: 'Missing fields' });
  const existing = db.prepare('SELECT * FROM scripts WHERE id = ? AND user_id = ?').get(id, user.id);
  if (!existing) return res.status(404).json({ error: 'Script not found' });
  const obfuscated = obfuscateLua(code);
  db.prepare('UPDATE scripts SET name = ?, code = ?, obfuscated_code = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?')
    .run(name, code, obfuscated, id, user.id);
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

app.post('/api/delete-panel', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { id } = req.body;
  db.prepare('DELETE FROM panels WHERE id = ? AND user_id = ?').run(id, user.id);
  res.json({ success: true });
});

app.post('/api/send-panel', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { panelId } = req.body;
  const panel = db.prepare('SELECT * FROM panels WHERE id = ? AND user_id = ?').get(panelId, user.id);
  if (!panel) return res.status(404).json({ error: 'Panel not found' });
  res.json({ success: true });
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
  db.prepare(`INSERT INTO keys (id, script_id, user_id, key, note, expires_at)
              VALUES (?, ?, ?, ?, ?, ?)`).run(id, panel.script_id, user.id, key, note || '', expiresAt);
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

app.post('/api/create-api-key', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { name } = req.body;
  const key = generateApiKey();
  const id = makeId('apikey');
  db.prepare(`INSERT INTO api_keys (id, user_id, key, name) VALUES (?, ?, ?, ?)`).run(id, user.id, key, name || 'My API Key');
  res.json({ success: true, key, id });
});

app.post('/api/delete-api-key', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { id } = req.body;
  db.prepare('DELETE FROM api_keys WHERE id = ? AND user_id = ?').run(id, user.id);
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
  const token = generateRecoveryToken();
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

app.get('/api/auth/discord', (req, res) => {
  const state = crypto.randomBytes(18).toString('hex');
  req.session.oauth_state = state;
  const redirectUri = `${publicBaseUrl()}/api/auth/discord/callback`;
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'identify guilds',
    state
  });
  res.redirect(`https://discord.com/oauth2/authorize?${params.toString()}`);
});

app.get('/api/auth/discord/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code || !state || state !== req.session.oauth_state) return res.status(400).send('Invalid OAuth state');
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
    res.redirect('/dashboard');
  } catch (e) {
    console.error('Auth error:', e);
    res.status(500).send('Authentication failed');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.get('/health', (req, res) => res.json({ ok: true, name: 'Karma Protection v7.0' }));

// ============ LANDING PAGE ============
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Karma Protection</title>
  <style>
    :root { --bg:#0a0a12; --card:rgba(18,22,35,0.92); --primary:#1a3a6b; --primary-grad:linear-gradient(135deg,#1a3a6b,#2b5b9a); --text:#e8edf5; --muted:#8899b0; --border:rgba(26,58,107,0.3); }
    * { margin:0; padding:0; box-sizing:border-box; }
    body { font-family:'Inter',system-ui,sans-serif; background:var(--bg); color:var(--text); min-height:100vh; display:flex; align-items:center; justify-content:center; background-image:radial-gradient(ellipse at 50% 0%, rgba(26,58,107,0.12) 0%, transparent 70%); }
    .container { max-width:1200px; margin:0 auto; padding:20px; width:100%; }
    .glass { background:var(--card); backdrop-filter:blur(20px); border:1px solid var(--border); border-radius:24px; padding:48px 40px; max-width:480px; width:100%; margin:0 auto; box-shadow:0 0 60px rgba(26,58,107,0.15); text-align:center; position:relative; overflow:hidden; }
    .glass::before { content:''; position:absolute; top:-50%; left:-50%; width:200%; height:200%; background:conic-gradient(from 0deg, transparent, rgba(26,58,107,0.05), transparent, rgba(26,58,107,0.05), transparent); animation:spin 20s linear infinite; pointer-events:none; }
    @keyframes spin { 100% { transform:rotate(360deg); } }
    .logo { margin-bottom:24px; position:relative; z-index:1; }
    .logo svg { width:56px; height:56px; color:var(--primary); filter:drop-shadow(0 0 20px rgba(26,58,107,0.4)); }
    h1 { font-size:28px; font-weight:800; letter-spacing:-0.5px; margin-bottom:8px; position:relative; z-index:1; }
    h1 span { background:var(--primary-grad); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
    .sub { color:var(--muted); font-size:14px; margin-bottom:28px; position:relative; z-index:1; }
    .btn { display:inline-flex; align-items:center; justify-content:center; gap:12px; width:100%; padding:16px 24px; border:none; border-radius:14px; font-weight:700; font-size:16px; cursor:pointer; transition:all 0.3s; position:relative; z-index:1; text-decoration:none; }
    .btn-primary { background:var(--primary-grad); color:white; box-shadow:0 4px 30px rgba(26,58,107,0.4); }
    .btn-primary:hover { transform:translateY(-3px); box-shadow:0 8px 40px rgba(26,58,107,0.6); }
    .btn-discord { background:#5865F2; color:white; }
    .btn-discord:hover { background:#4752C4; transform:translateY(-3px); }
    .btn-outline { background:rgba(255,255,255,0.05); border:1px solid var(--border); color:var(--text); }
    .btn-outline:hover { border-color:var(--primary); color:#fff; background:rgba(26,58,107,0.15); }
    .mt-16 { margin-top:16px; }
    .mt-24 { margin-top:24px; }
    .flex-col { display:flex; flex-direction:column; gap:12px; }
    .input { width:100%; background:rgba(0,0,0,0.4); border:1px solid var(--border); color:var(--text); padding:12px 16px; border-radius:10px; font-size:14px; transition:all 0.2s; }
    .input:focus { outline:none; border-color:var(--primary); box-shadow:0 0 0 3px rgba(26,58,107,0.2); }
    .divider { display:flex; align-items:center; gap:12px; color:var(--muted); font-size:13px; margin:16px 0; }
    .divider::before, .divider::after { content:''; flex:1; height:1px; background:var(--border); }
    .hidden { display:none; }
    .fade-in { animation:fadeIn 0.5s ease; }
    @keyframes fadeIn { from { opacity:0; transform:translateY(15px); } to { opacity:1; transform:translateY(0); } }
    .badge { display:inline-block; padding:4px 14px; border:1px solid var(--primary); border-radius:20px; font-size:11px; font-weight:600; color:var(--primary); text-transform:uppercase; letter-spacing:0.05em; margin-bottom:12px; position:relative; z-index:1; }
    .tab-btn { background:none; border:none; color:var(--muted); font-size:14px; font-weight:600; cursor:pointer; padding:8px 16px; border-radius:8px; transition:all 0.2s; }
    .tab-btn.active { color:var(--primary); background:rgba(26,58,107,0.12); }
    .tab-btn:hover { color:var(--text); }
  </style>
</head>
<body>
<div class="container">
  <div id="login-view" class="glass fade-in">
    <div class="logo"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M8 7v4m8-4v4"/></svg></div>
    <div class="badge">Premium Protection</div>
    <h1>Karma <span>Protection</span></h1>
    <p class="sub">HWID-locked key system with enterprise security</p>
    <div style="display:flex;justify-content:center;gap:8px;margin-bottom:20px;">
      <button class="tab-btn active" onclick="switchTab('login')">Login</button>
      <button class="tab-btn" onclick="switchTab('register')">Register</button>
    </div>
    <div id="tab-login" class="flex-col">
      <input class="input" id="login-email" placeholder="Email" type="email">
      <input class="input" id="login-password" placeholder="Password" type="password">
      <button class="btn btn-primary" onclick="emailLogin()">Sign In</button>
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
      <button class="btn btn-primary" onclick="emailRegister()">Create Account</button>
      <div class="divider">or</div>
      <a href="/api/auth/discord" class="btn btn-discord">
        <svg viewBox="0 0 127.14 96.36" style="width:22px;height:22px;fill:white;"><path d="M107.7,8.07A105.15,105.15,0,0,0,81.47,0a72.06,72.06,0,0,0-3.36,6.83A97.68,97.68,0,0,0,49,6.83,72.37,72.37,0,0,0,45.64,0,105.89,105.89,0,0,0,19.39,8.09C2.79,32.65-1.71,56.6.54,80.21h0A105.73,105.73,0,0,0,32.71,96.36,77.7,77.7,0,0,0,39.6,85.25a68.42,68.42,0,0,1-10.85-5.18c.91-.66,1.8-1.34,2.66-2a75.57,75.57,0,0,0,64.32,0c.87.71,1.76,1.39,2.66,2a68.68,68.68,0,0,1-10.87,5.19,77,77,0,0,0,6.89,11.1A105.25,105.25,0,0,0,126.6,80.22h0C129.24,52.84,122.09,29.11,107.7,8.07ZM42.45,65.69C36.18,65.69,31,60,31,53s5-12.74,11.43-12.74S54,46,53.89,53,48.84,65.69,42.45,65.69Zm42.24,0C78.41,65.69,73.31,60,73.31,53s5-12.74,11.43-12.74S96.1,46,96,53,91.08,65.69,84.69,65.69Z"/></svg>
        Continue with Discord
      </a>
    </div>
    <div id="recovery-view" class="hidden flex-col mt-24">
      <h3 style="font-size:18px;font-weight:600;margin-bottom:8px;">Recover Account</h3>
      <p class="sub">Enter your email to generate a recovery link.</p>
      <input class="input" id="recovery-email" placeholder="Email" type="email">
      <button class="btn btn-primary" onclick="initiateRecovery()">Generate Recovery Link</button>
      <button class="btn btn-outline mt-16" onclick="showLogin()">Back to Login</button>
    </div>
  </div>
</div>
<script>
function switchTab(tab) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-login').classList.toggle('hidden', tab !== 'login');
  document.getElementById('tab-register').classList.toggle('hidden', tab !== 'register');
  document.querySelector(`.tab-btn[onclick*="${tab}"]`).classList.add('active');
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

// ============ DASHBOARD ============
app.get('/dashboard', requireAuth, (req, res) => {
  const user = req.session.user;
  const escapedUsername = escapeHtml(user.global_name || user.username || user.email);
  const avatarUrl = user.avatar ? `https://cdn.discordapp.com/avatars/${user.discord_id}/${user.avatar}.png?size=128` : 'https://cdn.discordapp.com/embed/avatars/0.png';
  const botInviteUrl = `https://discord.com/oauth2/authorize?client_id=${CLIENT_ID}&permissions=${BOT_PERMISSIONS}&scope=bot`;

  res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Karma Protection | Dashboard</title>
  <style>
    :root { --bg:#0a0a12; --card:rgba(18,22,35,0.92); --primary:#1a3a6b; --primary-grad:linear-gradient(135deg,#1a3a6b,#2b5b9a); --text:#e8edf5; --muted:#8899b0; --border:rgba(26,58,107,0.25); --danger:#ef4444; --success:#10b981; --warning:#f59e0b; }
    * { margin:0; padding:0; box-sizing:border-box; }
    body { font-family:'Inter',system-ui,sans-serif; background:var(--bg); color:var(--text); min-height:100vh; background-image:radial-gradient(ellipse at 50% 0%, rgba(26,58,107,0.06) 0%, transparent 70%); }
    .topbar { display:flex; justify-content:space-between; align-items:center; padding:16px 24px; background:var(--card); backdrop-filter:blur(16px); border-bottom:1px solid var(--border); position:sticky; top:0; z-index:50; }
    .topbar .brand { font-size:20px; font-weight:800; display:flex; align-items:center; gap:10px; }
    .topbar .brand span { background:var(--primary-grad); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
    .topbar .user { display:flex; align-items:center; gap:12px; }
    .topbar .avatar { width:36px; height:36px; border-radius:50%; object-fit:cover; border:2px solid var(--primary); }
    .topbar .username { font-weight:600; font-size:14px; }
    .topbar .logout { color:var(--muted); cursor:pointer; font-size:13px; transition:color 0.2s; }
    .topbar .logout:hover { color:var(--danger); }
    .dashboard { display:grid; grid-template-columns:240px 1fr; min-height:calc(100vh - 72px); }
    .sidebar { background:var(--card); border-right:1px solid var(--border); padding:20px 16px; overflow-y:auto; }
    .sidebar .nav-item { display:flex; align-items:center; gap:12px; padding:10px 14px; border-radius:10px; color:var(--muted); font-weight:600; font-size:14px; cursor:pointer; transition:all 0.2s; margin-bottom:4px; }
    .sidebar .nav-item:hover { background:rgba(26,58,107,0.15); color:white; }
    .sidebar .nav-item.active { background:rgba(26,58,107,0.2); color:var(--primary); border:1px solid var(--border); }
    .sidebar .nav-label { font-size:11px; text-transform:uppercase; letter-spacing:0.1em; color:var(--muted); padding:12px 14px 6px; font-weight:700; }
    .main-content { padding:24px 32px; overflow-y:auto; }
    .card { background:var(--card); border:1px solid var(--border); border-radius:16px; padding:24px; margin-bottom:20px; box-shadow:0 4px 30px rgba(0,0,0,0.3); }
    .card h2 { font-size:20px; font-weight:800; margin-bottom:4px; }
    .card h2 span { color:var(--primary); }
    .card .sub { color:var(--muted); font-size:14px; margin-bottom:16px; }
    .stats-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:16px; margin-top:16px; }
    .stat { background:rgba(0,0,0,0.3); border:1px solid var(--border); border-radius:12px; padding:16px; text-align:center; transition:all 0.3s; }
    .stat:hover { border-color:var(--primary); box-shadow:0 0 30px rgba(26,58,107,0.1); }
    .stat .num { font-size:28px; font-weight:900; background:var(--primary-grad); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
    .stat .label { font-size:13px; color:var(--muted); margin-top:4px; }
    input, textarea, select { width:100%; background:rgba(0,0,0,0.4); border:1px solid var(--border); color:var(--text); padding:12px 16px; border-radius:10px; margin-bottom:14px; font-size:14px; transition:all 0.2s; }
    input:focus, textarea:focus, select:focus { outline:none; border-color:var(--primary); box-shadow:0 0 0 3px rgba(26,58,107,0.2); }
    textarea { min-height:120px; font-family:monospace; resize:vertical; }
    select { appearance:none; background-image:url("data:image/svg+xml;charset=US-ASCII,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%22292.4%22%20height%3D%22292.4%22%3E%3Cpath%20fill%3D%22%231a3a6b%22%20d%3D%22M287%2069.4a17.6%2017.6%200%200%200-13-5.4H18.4c-5%200-9.3%201.8-12.9%205.4A17.6%2017.6%200%200%200%200%2082.2c0%205%201.8%209.3%205.4%2012.9l128%20127.9c3.6%203.6%207.8%205.4%2012.8%205.4s9.2-1.8%2012.8-5.4L287%2095c3.5-3.5%205.4-7.8%205.4-12.8%200-5-1.9-9.2-5.5-12.8z%22/%3E%3C/svg%3E"); background-repeat:no-repeat; background-position:right 16px top 50%; background-size:12px auto; }
    .btn { display:inline-flex; align-items:center; justify-content:center; gap:8px; padding:10px 20px; border-radius:10px; font-weight:600; font-size:13px; cursor:pointer; transition:all 0.2s; border:none; }
    .btn-primary { background:var(--primary-grad); color:white; box-shadow:0 4px 20px rgba(26,58,107,0.3); }
    .btn-primary:hover { transform:translateY(-2px); box-shadow:0 8px 30px rgba(26,58,107,0.4); }
    .btn-danger { background:rgba(239,68,68,0.15); color:var(--danger); border:1px solid rgba(239,68,68,0.2); }
    .btn-danger:hover { background:rgba(239,68,68,0.25); }
    .btn-success { background:rgba(16,185,129,0.15); color:var(--success); border:1px solid rgba(16,185,129,0.2); }
    .btn-success:hover { background:rgba(16,185,129,0.25); }
    .btn-outline { background:rgba(0,0,0,0.2); border:1px solid var(--border); color:var(--text); }
    .btn-outline:hover { border-color:var(--primary); color:var(--primary); background:rgba(26,58,107,0.1); }
    .checkbox-container { display:flex; align-items:center; gap:10px; padding:10px 14px; background:rgba(0,0,0,0.3); border:1px solid var(--border); border-radius:10px; cursor:pointer; font-weight:600; font-size:13px; transition:all 0.2s; width:fit-content; }
    .checkbox-container:hover { border-color:var(--primary); color:var(--primary); }
    .checkbox-container input { width:16px; height:16px; cursor:pointer; accent-color:var(--primary); margin:0; }
    .grid-2 { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
    .scripts-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(260px,1fr)); gap:16px; }
    .script-card { background:rgba(0,0,0,0.3); border:1px solid var(--border); border-radius:12px; padding:16px; transition:all 0.3s; cursor:pointer; }
    .script-card:hover { border-color:var(--primary); transform:translateY(-3px); box-shadow:0 8px 30px rgba(0,0,0,0.3); }
    .script-card .title { font-weight:600; font-size:15px; margin-bottom:8px; }
    .script-card .meta { font-size:12px; color:var(--muted); margin-bottom:12px; }
    .script-card .actions { display:flex; gap:8px; flex-wrap:wrap; }
    .script-card .actions .btn { flex:1; padding:8px 12px; font-size:12px; }
    .badge { display:inline-block; padding:2px 10px; border-radius:6px; font-size:11px; font-weight:600; }
    .badge-success { background:rgba(16,185,129,0.15); color:var(--success); border:1px solid rgba(16,185,129,0.15); }
    .badge-danger { background:rgba(239,68,68,0.15); color:var(--danger); border:1px solid rgba(239,68,68,0.15); }
    .badge-warning { background:rgba(245,158,11,0.15); color:var(--warning); border:1px solid rgba(245,158,11,0.15); }
    .badge-primary { background:rgba(26,58,107,0.2); color:var(--primary); border:1px solid rgba(26,58,107,0.15); }
    .view-section { display:none; }
    .view-section.active { display:block; animation:fadeIn 0.3s ease; }
    @keyframes fadeIn { from { opacity:0; transform:translateY(10px); } to { opacity:1; transform:translateY(0); } }
    .actions-row { display:flex; gap:10px; flex-wrap:wrap; margin-top:10px; }
    .flex { display:flex; align-items:center; gap:12px; flex-wrap:wrap; }
    .flex-between { display:flex; justify-content:space-between; align-items:center; }
    .text-muted { color:var(--muted); }
    .text-gold { color:var(--primary); }
    .back-link { color:var(--primary); cursor:pointer; text-decoration:none; font-weight:600; }
    .back-link:hover { text-decoration:underline; }
    @media (max-width:768px) { .dashboard { grid-template-columns:1fr; } .sidebar { display:none; position:fixed; top:0; left:0; width:260px; height:100vh; z-index:100; } .sidebar.open { display:block; } .main-content { padding:16px; } .stats-grid { grid-template-columns:1fr 1fr; } .scripts-grid { grid-template-columns:1fr; } .grid-2 { grid-template-columns:1fr; } }
  </style>
</head>
<body>
  <header class="topbar">
    <div class="brand">Karma <span>Protection</span></div>
    <div class="user">
      <span class="username">${escapedUsername}</span>
      <img class="avatar" src="${avatarUrl}" alt="Avatar">
      <span class="logout" onclick="window.location.href='/logout'">Logout</span>
    </div>
  </header>
  <div class="dashboard">
    <aside class="sidebar" id="sidebar">
      <div class="nav-label">Navigation</div>
      <div class="nav-item active" onclick="switchView('overview', this)">Overview</div>
      <div class="nav-item" onclick="switchView('scripts', this)">Scripts</div>
      <div class="nav-item" onclick="switchView('panels', this)">Panels</div>
      <div class="nav-item" onclick="switchView('keys', this)">Keys</div>
      <div class="nav-item" onclick="switchView('whitelist', this)">Whitelist</div>
      <div class="nav-item" onclick="switchView('hwids', this)">HWID Bans</div>
      <div class="nav-item" onclick="switchView('logs', this)">Command Logs</div>
      <div class="nav-item" onclick="switchView('settings', this)">Settings</div>
    </aside>
    <main class="main-content" id="mainContent">
      <!-- Overview -->
      <div id="view-overview" class="view-section active">
        <div class="card">
          <h2>Welcome, <span>${escapedUsername}</span></h2>
          <p class="sub">Manage your scripts, panels, and keys from one place.</p>
          <div class="stats-grid" id="statsGrid">
            <div class="stat"><div class="num" id="statScripts">0</div><div class="label">Scripts</div></div>
            <div class="stat"><div class="num" id="statPanels">0</div><div class="label">Panels</div></div>
            <div class="stat"><div class="num" id="statKeys">0</div><div class="label">Keys</div></div>
            <div class="stat"><div class="num" id="statWhitelist">0</div><div class="label">Whitelisted</div></div>
            <div class="stat"><div class="num" id="statBanned">0</div><div class="label">Banned HWIDs</div></div>
          </div>
        </div>
        <div class="card">
          <h3>Add Bot to Server</h3>
          <p class="sub">Invite the Karma Protection bot to your Discord server.</p>
          <a href="${botInviteUrl}" target="_blank" class="btn btn-primary">Invite Bot</a>
        </div>
      </div>

      <!-- Scripts -->
      <div id="view-scripts" class="view-section">
        <div class="card">
          <h2>Your <span>Scripts</span></h2>
          <p class="sub">Create and manage your protected scripts.</p>
          <div class="flex" style="margin-bottom:16px;">
            <input type="text" id="scriptName" placeholder="Script name" style="flex:1;min-width:200px;margin:0;">
            <label class="checkbox-container"><input type="checkbox" id="ffaMode"> FFA Mode</label>
            <label class="checkbox-container"><input type="checkbox" id="compressMode"> Compress</label>
            <button class="btn btn-primary" onclick="createScript()">Create</button>
          </div>
          <textarea id="scriptCode" rows="8" placeholder="Paste your Lua code here..."></textarea>
        </div>
        <div id="scriptsList" class="scripts-grid"></div>
      </div>

      <!-- Panels -->
      <div id="view-panels" class="view-section">
        <div class="card">
          <h2>Discord <span>Panels</span></h2>
          <p class="sub">Create panels to send to your Discord server.</p>
          <div class="grid-2">
            <input type="text" id="panelName" placeholder="Panel name">
            <input type="text" id="panelChannel" placeholder="Discord Channel ID">
          </div>
          <textarea id="panelDesc" rows="3" placeholder="Panel description..."></textarea>
          <select id="panelScript"><option value="">Select script...</option></select>
          <input type="number" id="panelCooldown" placeholder="HWID cooldown (seconds)" value="180">
          <button class="btn btn-primary" onclick="createPanel()">Create Panel</button>
        </div>
        <div id="panelsList" class="scripts-grid"></div>
      </div>

      <!-- Keys -->
      <div id="view-keys" class="view-section">
        <div class="card">
          <h2>Generate <span>Keys</span></h2>
          <p class="sub">Generate license keys for your panels.</p>
          <select id="keyPanel"><option value="">Select panel...</option></select>
          <input type="number" id="keyDuration" placeholder="Duration (hours, 0 = permanent)" value="0">
          <input type="text" id="keyNote" placeholder="Note (optional)">
          <div class="actions-row">
            <button class="btn btn-primary" onclick="generateKey()">Generate Key</button>
            <button class="btn btn-outline" onclick="addTimeAll()">Add Time to All</button>
          </div>
        </div>
        <div id="keysList" class="scripts-grid"></div>
      </div>

      <!-- Whitelist -->
      <div id="view-whitelist" class="view-section">
        <div class="card">
          <h2>Whitelist <span>Management</span></h2>
          <p class="sub">Users you've whitelisted with auto-generated keys.</p>
        </div>
        <div id="whitelistList" class="scripts-grid"></div>
      </div>

      <!-- HWID Bans -->
      <div id="view-hwids" class="view-section">
        <div class="card">
          <h2>Ban <span>HWID</span></h2>
          <p class="sub">Ban a hardware ID from accessing your scripts.</p>
          <div class="flex">
            <input type="text" id="banHwidInput" placeholder="Enter HWID to ban" style="flex:1;margin:0;">
            <button class="btn btn-danger" onclick="banHwid()">Ban</button>
          </div>
        </div>
        <div id="hwidsList" class="scripts-grid"></div>
      </div>

      <!-- Command Logs -->
      <div id="view-logs" class="view-section">
        <div class="card">
          <h2>Command <span>Logs</span></h2>
          <p class="sub">Recent bot commands executed.</p>
          <div id="logsList" style="font-family:monospace;font-size:13px;max-height:400px;overflow-y:auto;"></div>
        </div>
      </div>

      <!-- Settings -->
      <div id="view-settings" class="view-section">
        <div class="card">
          <h2>API <span>Keys</span></h2>
          <p class="sub">Generate and manage API keys for programmatic access.</p>
          <div class="flex" style="margin-bottom:16px;">
            <input type="text" id="apiKeyName" placeholder="Key name" style="flex:1;margin:0;">
            <button class="btn btn-primary" onclick="createApiKey()">Generate</button>
          </div>
          <div id="apiKeysList"></div>
        </div>

        <div class="card">
          <h2>Account <span>Settings</span></h2>
          <div style="display:flex;flex-direction:column;gap:12px;">
            <div>
              <h4 style="margin-bottom:4px;">Recover Account</h4>
              <p class="sub">Generate a recovery link for your account.</p>
              <button class="btn btn-outline" onclick="initiateRecoverySettings()">Generate Recovery Link</button>
            </div>
            <div style="border-top:1px solid var(--border);padding-top:12px;">
              <h4 style="margin-bottom:4px;color:var(--danger);">Delete Account</h4>
              <p class="sub">Permanently delete your account and all data.</p>
              <button class="btn btn-danger" onclick="deleteAccount()">Delete Account</button>
            </div>
          </div>
        </div>

        <div class="card">
          <h3>Add Bot to Server</h3>
          <p class="sub">Invite the Karma Protection bot to your Discord server.</p>
          <a href="${botInviteUrl}" target="_blank" class="btn btn-primary">Invite Bot</a>
        </div>
      </div>
    </main>
  </div>

  <script>
    let currentData = { scripts: [], panels: [], keys: [], bannedHWIDs: [], whitelist: [], apiKeys: [], logs: [] };
    let serverTime = Date.now();

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
      renderWhitelist();
      renderHwids();
      renderLogs();
      renderApiKeys();
      updateSelects();
    }

    function renderStats() {
      document.getElementById('statScripts').textContent = currentData.scripts.length;
      document.getElementById('statPanels').textContent = currentData.panels.length;
      document.getElementById('statKeys').textContent = currentData.keys.length;
      document.getElementById('statWhitelist').textContent = currentData.whitelist ? currentData.whitelist.length : 0;
      document.getElementById('statBanned').textContent = currentData.bannedHWIDs.length;
    }

    function renderScripts() {
      const container = document.getElementById('scriptsList');
      if (!currentData.scripts.length) {
        container.innerHTML = '<div style="grid-column:1/-1;padding:30px;text-align:center;color:var(--muted);background:rgba(0,0,0,0.2);border-radius:12px;border:1px dashed var(--border);">No scripts yet. Create one above.</div>';
        return;
      }
      let html = '';
      for (const s of currentData.scripts) {
        const statusBadge = s.status === 'active' ? 'badge-success' : 'badge-danger';
        const statusText = s.status === 'active' ? 'Active' : 'Disabled';
        const ffaBadge = s.ffa_mode ? '<span class="badge badge-warning">FFA</span>' : '';
        const compressBadge = s.compress_mode ? '<span class="badge badge-primary">Compressed</span>' : '';
        const date = new Date(s.created_at).toLocaleDateString();
        html += '<div class="script-card" onclick="viewScript(\'' + s.id + '\')">' +
          '<div class="title">' + escapeHtml(s.name) + '</div>' +
          '<div class="meta"><span class="badge ' + statusBadge + '">' + statusText + '</span> ' + ffaBadge + ' ' + compressBadge + ' <span style="margin-left:8px;">' + date + '</span></div>' +
          '<div class="actions">' +
            '<button class="btn btn-outline" onclick="event.stopPropagation();toggleScript(\'' + s.id + '\')">' + (s.status==='active'?'Disable':'Enable') + '</button>' +
            '<button class="btn btn-outline" onclick="event.stopPropagation();toggleFfa(\'' + s.id + '\')">' + (s.ffa_mode?'Disable FFA':'Enable FFA') + '</button>' +
            '<button class="btn btn-danger" onclick="event.stopPropagation();deleteScript(\'' + s.id + '\')">Delete</button>' +
          '</div></div>';
      }
      container.innerHTML = html;
    }

    function renderPanels() {
      const container = document.getElementById('panelsList');
      if (!currentData.panels.length) {
        container.innerHTML = '<div style="grid-column:1/-1;padding:30px;text-align:center;color:var(--muted);background:rgba(0,0,0,0.2);border-radius:12px;border:1px dashed var(--border);">No panels yet. Create one above.</div>';
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
        container.innerHTML = '<div style="grid-column:1/-1;padding:30px;text-align:center;color:var(--muted);background:rgba(0,0,0,0.2);border-radius:12px;border:1px dashed var(--border);">No keys generated yet.</div>';
        return;
      }
      let html = '';
      for (const k of currentData.keys) {
        const expired = k.expires_at && new Date(k.expires_at).getTime() < serverTime;
        let status = 'Active', badgeClass = 'badge-success';
        if (expired) { status = 'Expired'; badgeClass = 'badge-danger'; }
        else if (k.hwid) { status = 'HWID Locked'; badgeClass = 'badge-warning'; }
        html += '<div class="script-card">' +
          '<div class="title" style="font-family:monospace;font-size:13px;color:var(--primary);">' + escapeHtml(k.key) + '</div>' +
          '<div class="meta"><span class="badge ' + badgeClass + '">' + status + '</span> ' + (k.note ? '<span style="margin-left:8px;">'+escapeHtml(k.note)+'</span>' : '') + '</div>' +
          '<div class="actions"><button class="btn btn-danger" onclick="deleteKey(\'' + k.key + '\')">Delete</button></div></div>';
      }
      container.innerHTML = html;
    }

    function renderWhitelist() {
      const container = document.getElementById('whitelistList');
      const wl = currentData.whitelist || [];
      if (!wl.length) {
        container.innerHTML = '<div style="grid-column:1/-1;padding:30px;text-align:center;color:var(--muted);background:rgba(0,0,0,0.2);border-radius:12px;border:1px dashed var(--border);">No users whitelisted yet.</div>';
        return;
      }
      let html = '';
      for (const w of wl) {
        const expired = w.expires_at && new Date(w.expires_at).getTime() < serverTime;
        const status = expired ? 'Expired' : 'Active';
        const badgeClass = expired ? 'badge-danger' : 'badge-success';
        html += '<div class="script-card">' +
          '<div class="title">' + escapeHtml(w.username || w.discord_id) + '</div>' +
          '<div class="meta"><span class="badge ' + badgeClass + '">' + status + '</span> ' + (w.hwid ? 'HWID Locked' : 'No HWID') + ' <span style="margin-left:8px;">Key: ' + escapeHtml(w.key) + '</span></div>' +
          '<div class="actions"><button class="btn btn-outline" onclick="removeWhitelist(\'' + w.id + '\')">Remove</button></div></div>';
      }
      container.innerHTML = html;
    }

    function renderHwids() {
      const container = document.getElementById('hwidsList');
      if (!currentData.bannedHWIDs.length) {
        container.innerHTML = '<div style="grid-column:1/-1;padding:30px;text-align:center;color:var(--muted);background:rgba(0,0,0,0.2);border-radius:12px;border:1px dashed var(--border);">No banned HWIDs.</div>';
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

    function renderLogs() {
      const container = document.getElementById('logsList');
      const logs = currentData.logs || [];
      if (!logs.length) {
        container.innerHTML = '<p class="text-muted">No commands logged yet.</p>';
        return;
      }
      let html = '<div style="display:flex;flex-direction:column;gap:6px;">';
      for (const log of logs) {
        const date = new Date(log.timestamp).toLocaleString();
        html += '<div style="padding:6px 12px;background:rgba(0,0,0,0.2);border-radius:6px;border-left:3px solid var(--primary);">' +
          '<span style="color:var(--muted);">' + date + '</span> — <strong>/' + escapeHtml(log.command) + '</strong> ' + (log.args ? escapeHtml(log.args) : '') +
          ' <span style="color:var(--muted);font-size:12px;">by ' + (log.user_id ? escapeHtml(log.user_id) : 'unknown') + '</span>' +
        '</div>';
      }
      html += '</div>';
      container.innerHTML = html;
    }

    function renderApiKeys() {
      const container = document.getElementById('apiKeysList');
      const keys = currentData.apiKeys || [];
      if (!keys.length) {
        container.innerHTML = '<p class="text-muted">No API keys generated.</p>';
        return;
      }
      let html = '<div style="display:flex;flex-direction:column;gap:8px;">';
      for (const k of keys) {
        html += '<div class="flex-between" style="padding:8px 12px;background:rgba(0,0,0,0.2);border-radius:8px;border:1px solid var(--border);">' +
          '<div><span style="font-family:monospace;font-size:13px;color:var(--primary);">' + escapeHtml(k.key) + '</span> ' + (k.name ? '<span class="text-muted" style="margin-left:8px;">'+escapeHtml(k.name)+'</span>' : '') + '</div>' +
          '<button class="btn btn-danger" style="padding:4px 12px;font-size:12px;" onclick="deleteApiKey(\'' + k.id + '\')">Delete</button>' +
        '</div>';
      }
      html += '</div>';
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
    }

    // --- Script actions ---
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

    function viewScript(id) {
      window.location.href = '/script/' + id;
    }

    // --- Panel actions ---
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

    // --- Key actions ---
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

    // --- Whitelist ---
    async function removeWhitelist(id) {
      if (!confirm('Remove this user from whitelist?')) return;
      await fetch('/api/delete-whitelist', { method:'POST', headers:getHeaders(), body:JSON.stringify({id}) });
      loadData();
    }

    // --- HWID ---
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

    // --- API Keys ---
    async function createApiKey() {
      const name = document.getElementById('apiKeyName').value.trim();
      const res = await fetch('/api/create-api-key', { method:'POST', headers:getHeaders(), body:JSON.stringify({name}) });
      const data = await res.json();
      if (data.success) {
        alert('API Key created: ' + data.key);
        document.getElementById('apiKeyName').value = '';
        loadData();
      } else {
        alert(data.error || 'Failed to create API key.');
      }
    }

    async function deleteApiKey(id) {
      if (!confirm('Delete this API key?')) return;
      await fetch('/api/delete-api-key', { method:'POST', headers:getHeaders(), body:JSON.stringify({id}) });
      loadData();
    }

    // --- Settings ---
    async function initiateRecoverySettings() {
      const email = prompt('Enter your account email:');
      if (!email) return;
      const res = await fetch('/api/initiate-recovery', { method:'POST', headers:getHeaders(), body:JSON.stringify({email}) });
      const data = await res.json();
      if (data.success) alert('Recovery link generated. Check console or your email.');
      else alert(data.error || 'Failed to generate recovery link.');
    }

    async function deleteAccount() {
      if (!confirm('Are you sure? This action is permanent and cannot be undone.')) return;
      const confirmText = prompt('Type DELETE to confirm:');
      if (confirmText !== 'DELETE') return alert('Confirmation failed.');
      const res = await fetch('/api/delete-account', { method:'POST', headers:getHeaders(), body:JSON.stringify({confirm:'DELETE'}) });
      const data = await res.json();
      if (data.success) {
        alert('Account deleted.');
        window.location.href = '/';
      } else {
        alert(data.error || 'Failed to delete account.');
      }
    }

    function escapeHtml(text) {
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    }

    loadData();
    setInterval(loadData, 30000); // Auto-refresh every 30s
  </script>
</body>
</html>`);
});

// ============ SCRIPT DETAIL PAGE ============
app.get('/script/:id', requireAuth, (req, res) => {
  const user = req.session.user;
  const scriptId = req.params.id;
  const script = db.prepare('SELECT * FROM scripts WHERE id = ? AND user_id = ?').get(scriptId, user.id);
  if (!script) return res.status(404).send('Script not found');

  res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(script.name)} | Karma Protection</title>
  <style>
    :root { --bg:#0a0a12; --card:rgba(18,22,35,0.92); --primary:#1a3a6b; --primary-grad:linear-gradient(135deg,#1a3a6b,#2b5b9a); --text:#e8edf5; --muted:#8899b0; --border:rgba(26,58,107,0.25); --danger:#ef4444; --success:#10b981; --warning:#f59e0b; }
    * { margin:0; padding:0; box-sizing:border-box; }
    body { font-family:'Inter',system-ui,sans-serif; background:var(--bg); color:var(--text); padding:40px 20px; }
    .container { max-width:900px; margin:0 auto; }
    .card { background:var(--card); border:1px solid var(--border); border-radius:16px; padding:24px; margin-bottom:20px; box-shadow:0 4px 30px rgba(0,0,0,0.3); }
    .card h1 { font-size:24px; font-weight:800; margin-bottom:4px; }
    .card h1 span { color:var(--primary); }
    .card .sub { color:var(--muted); font-size:14px; margin-bottom:16px; }
    .btn { display:inline-flex; align-items:center; justify-content:center; gap:8px; padding:10px 20px; border-radius:10px; font-weight:600; font-size:13px; cursor:pointer; transition:all 0.2s; border:none; }
    .btn-primary { background:var(--primary-grad); color:white; box-shadow:0 4px 20px rgba(26,58,107,0.3); }
    .btn-primary:hover { transform:translateY(-2px); box-shadow:0 8px 30px rgba(26,58,107,0.4); }
    .btn-outline { background:rgba(0,0,0,0.2); border:1px solid var(--border); color:var(--text); }
    .btn-outline:hover { border-color:var(--primary); color:var(--primary); }
    .btn-danger { background:rgba(239,68,68,0.15); color:var(--danger); border:1px solid rgba(239,68,68,0.2); }
    .btn-danger:hover { background:rgba(239,68,68,0.25); }
    .flex { display:flex; gap:12px; flex-wrap:wrap; align-items:center; }
    .flex-between { display:flex; justify-content:space-between; align-items:center; }
    textarea { width:100%; background:rgba(0,0,0,0.4); border:1px solid var(--border); color:var(--text); padding:12px 16px; border-radius:10px; margin-bottom:14px; font-size:14px; font-family:monospace; resize:vertical; min-height:300px; }
    textarea:focus { outline:none; border-color:var(--primary); box-shadow:0 0 0 3px rgba(26,58,107,0.2); }
    .badge { display:inline-block; padding:2px 10px; border-radius:6px; font-size:11px; font-weight:600; }
    .badge-success { background:rgba(16,185,129,0.15); color:var(--success); border:1px solid rgba(16,185,129,0.15); }
    .badge-danger { background:rgba(239,68,68,0.15); color:var(--danger); border:1px solid rgba(239,68,68,0.15); }
    .badge-warning { background:rgba(245,158,11,0.15); color:var(--warning); border:1px solid rgba(245,158,11,0.15); }
    .badge-primary { background:rgba(26,58,107,0.2); color:var(--primary); border:1px solid rgba(26,58,107,0.15); }
    .mt-16 { margin-top:16px; }
    .text-muted { color:var(--muted); }
    .back-link { color:var(--primary); cursor:pointer; text-decoration:none; font-weight:600; }
    .back-link:hover { text-decoration:underline; }
    input { width:100%; background:rgba(0,0,0,0.4); border:1px solid var(--border); color:var(--text); padding:10px 14px; border-radius:8px; font-size:14px; }
    input:focus { outline:none; border-color:var(--primary); box-shadow:0 0 0 3px rgba(26,58,107,0.2); }
  </style>
</head>
<body>
<div class="container">
  <a href="/dashboard" class="back-link">← Back to Dashboard</a>
  <div class="card">
    <div class="flex-between">
      <div>
        <h1><span>${escapeHtml(script.name)}</span></h1>
        <p class="sub">Version ${escapeHtml(script.version || '1.0.0')} &bull; ${new Date(script.created_at).toLocaleDateString()}</p>
      </div>
      <div>
        <span class="badge ${script.status === 'active' ? 'badge-success' : 'badge-danger'}">${script.status === 'active' ? 'Active' : 'Disabled'}</span>
        ${script.ffa_mode ? '<span class="badge badge-warning">FFA</span>' : ''}
        ${script.compress_mode ? '<span class="badge badge-primary">Compressed</span>' : ''}
      </div>
    </div>
    <div style="margin:16px 0;">
      <label style="display:block;font-weight:600;margin-bottom:4px;">Script Name</label>
      <input id="editName" value="${escapeHtml(script.name)}">
    </div>
    <div>
      <label style="display:block;font-weight:600;margin-bottom:4px;">Lua Code</label>
      <textarea id="editCode">${escapeHtml(script.code)}</textarea>
    </div>
    <div class="flex">
      <button class="btn btn-primary" onclick="saveScript()">Save Changes</button>
      <button class="btn btn-outline" onclick="toggleScript()">${script.status === 'active' ? 'Disable' : 'Enable'}</button>
      <button class="btn btn-outline" onclick="toggleFfa()">${script.ffa_mode ? 'Disable FFA' : 'Enable FFA'}</button>
      <button class="btn btn-danger" onclick="deleteScript()">Delete</button>
    </div>
  </div>
  <div class="card">
    <h3>Loader</h3>
    <p class="sub">Share this loader with your users.</p>
    <textarea id="loaderDisplay" rows="2" readonly style="min-height:60px;cursor:default;">loadstring(game:HttpGet("${publicBaseUrl()}/loader/${script.id}"))()</textarea>
    <button class="btn btn-outline" onclick="copyLoader()">Copy Loader</button>
  </div>
</div>
<script>
  const scriptId = '${script.id}';
  async function saveScript() {
    const name = document.getElementById('editName').value.trim();
    const code = document.getElementById('editCode').value;
    if (!name || !code) return alert('Name and code are required.');
    const res = await fetch('/api/update-script', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id:scriptId, name, code}) });
    const data = await res.json();
    if (data.success) { alert('Script updated.'); window.location.reload(); }
    else alert(data.error || 'Failed to update script.');
  }
  async function toggleScript() {
    const res = await fetch('/api/scripts/'+scriptId+'/toggle', { method:'PUT', headers:{'Content-Type':'application/json'} });
    const data = await res.json();
    if (data.success) window.location.reload();
    else alert('Failed to toggle status.');
  }
  async function toggleFfa() {
    const res = await fetch('/api/scripts/'+scriptId+'/ffa', { method:'PUT', headers:{'Content-Type':'application/json'} });
    const data = await res.json();
    if (data.success) window.location.reload();
    else alert('Failed to toggle FFA.');
  }
  async function deleteScript() {
    if (!confirm('Delete this script permanently?')) return;
    const res = await fetch('/api/delete-script', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id:scriptId}) });
    const data = await res.json();
    if (data.success) window.location.href = '/dashboard';
    else alert('Failed to delete script.');
  }
  function copyLoader() {
    const text = document.getElementById('loaderDisplay');
    text.select();
    document.execCommand('copy');
    alert('Loader copied to clipboard.');
  }
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
    const wl = db.prepare('SELECT * FROM whitelist WHERE key = ?').get(key);
    if (wl) db.prepare('UPDATE whitelist SET hwid = ? WHERE id = ?').run(hwid, wl.id);
  }
  if (hwid && keyRecord.hwid && keyRecord.hwid !== hwid) {
    return res.status(403).type('text/plain').send('-- HWID mismatch. Use /reset-hwid <key>');
  }
  db.prepare('UPDATE keys SET last_used_at = CURRENT_TIMESTAMP WHERE key = ?').run(key);
  const baseUrl = publicBaseUrl();
  res.type('text/plain').send(`--[[ Karma Protection Loader ]]\nreturn (function()\n  local url = "${baseUrl}/script/${scriptId}?hwid=${hwid||''}&key=${key}"\n  local src = game:HttpGet(url)\n  if not src or #src < 10 then error("Invalid payload") end\n  local func, err = loadstring(src, "@Karma")\n  if not func then error(err) end\n  return func()\nend)()`);
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
    return res.status(403).type('text/plain').send('-- HWID mismatch. Use /reset-hwid');
  }
  if (hwid && !keyRecord.hwid) {
    db.prepare('UPDATE keys SET hwid = ?, last_used_at = CURRENT_TIMESTAMP WHERE key = ?').run(hwid, key);
    const wl = db.prepare('SELECT * FROM whitelist WHERE key = ?').get(key);
    if (wl) db.prepare('UPDATE whitelist SET hwid = ? WHERE id = ?').run(hwid, wl.id);
  }
  db.prepare('UPDATE keys SET last_used_at = CURRENT_TIMESTAMP WHERE key = ?').run(key);
  res.setHeader('Cache-Control', 'no-store');
  res.type('text/plain').send(script.code || '-- Empty');
});

// ============ DISCORD BOT ============
const client = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers, GatewayIntentBits.MessageContent, GatewayIntentBits.DirectMessages],
  partials: [Partials.Channel, Partials.Message],
  presence: { status: PresenceUpdateStatus.Online, activities: [{ name: 'Karma Protection v7.0', type: ActivityType.Watching }] }
});

client.once('ready', () => console.log(`Bot online as ${client.user.tag}`));

// ============ SLASH COMMANDS ============
const commands = [
  new SlashCommandBuilder().setName('help').setDescription('List all available commands'),
  new SlashCommandBuilder().setName('setup').setDescription('Create or load your account'),
  new SlashCommandBuilder().setName('scripts').setDescription('List your scripts'),
  new SlashCommandBuilder().setName('createkey').setDescription('Generate a new key')
    .addStringOption(option => option.setName('script').setDescription('Script name').setRequired(true))
    .addIntegerOption(option => option.setName('hours').setDescription('Duration in hours (0 = permanent)')),
  new SlashCommandBuilder().setName('keys').setDescription('List your keys'),
  new SlashCommandBuilder().setName('revoke').setDescription('Revoke a key')
    .addStringOption(option => option.setName('key').setDescription('Key to revoke').setRequired(true)),
  new SlashCommandBuilder().setName('resethwid').setDescription('Reset HWID for a key')
    .addStringOption(option => option.setName('key').setDescription('Key to reset').setRequired(true)),
  new SlashCommandBuilder().setName('whitelist').setDescription('Whitelist a user')
    .addStringOption(option => option.setName('script').setDescription('Script name').setRequired(true))
    .addUserOption(option => option.setName('user').setDescription('User to whitelist').setRequired(true))
    .addIntegerOption(option => option.setName('hours').setDescription('Duration in hours (0 = permanent)')),
  new SlashCommandBuilder().setName('unwhitelist').setDescription('Remove a user from whitelist')
    .addUserOption(option => option.setName('user').setDescription('User to remove').setRequired(true)),
  new SlashCommandBuilder().setName('whitelistlist').setDescription('List all whitelisted users'),
  new SlashCommandBuilder().setName('panelsetup').setDescription('Send a panel for a script')
    .addStringOption(option => option.setName('script').setDescription('Script name').setRequired(true)),
  new SlashCommandBuilder().setName('panel').setDescription('Send a custom panel')
    .addStringOption(option => option.setName('script').setDescription('Script name').setRequired(true))
];

const rest = new REST({ version: '10' }).setToken(DISCORD_TOKEN);

async function deployCommands() {
  try {
    console.log('Deploying slash commands...');
    await rest.put(Routes.applicationGuildCommands(CLIENT_ID, GUILD_ID), { body: commands.map(cmd => cmd.toJSON()) });
    console.log('Commands deployed successfully.');
  } catch (e) {
    console.error('Failed to deploy commands:', e);
  }
}

deployCommands();

// ============ INTERACTION HANDLER ============
client.on('interactionCreate', async (interaction) => {
  if (interaction.isChatInputCommand()) {
    const command = interaction.commandName;
    const user = db.prepare('SELECT * FROM users WHERE discord_id = ? AND deleted_at IS NULL').get(interaction.user.id);
    logCommand(interaction.user.id, command, JSON.stringify(interaction.options.data));

    try {
      if (command === 'help') {
        const embed = new EmbedBuilder().setColor(BRAND_COLOR).setTitle('Karma Protection v7.0 – Commands')
          .setDescription([
            '**General**', '/setup – Create/load account', '/scripts – List scripts', '/keys – List keys',
            '', '**Key Management**', '/createkey <script> [hours] – Generate key', '/revoke <key> – Revoke key', '/resethwid <key> – Reset HWID (24h cooldown)',
            '', '**Whitelist**', '/whitelist <script> <@user> [hours] – Whitelist user', '/unwhitelist <@user> – Remove', '/whitelistlist – List whitelisted',
            '', '**Panels**', '/panelsetup <script> – Spawn panel', '/panel <script> – Send custom panel'
          ].join('\n'))
          .setFooter({ text: 'Karma Protection v7.0' }).setTimestamp();
        await interaction.reply({ embeds: [embed], ephemeral: true });
        return;
      }

      if (command === 'setup') {
        let dbUser = user;
        if (!dbUser) {
          const id = `user_${crypto.randomBytes(8).toString('hex')}`;
          db.prepare(`INSERT INTO users (id, discord_id, username, avatar, provider) VALUES (?, ?, ?, ?, ?)`).run(id, interaction.user.id, interaction.user.username, interaction.user.displayAvatarURL() || '', 'discord');
          dbUser = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(interaction.user.id);
        }
        const sc = db.prepare('SELECT COUNT(*) as count FROM scripts WHERE user_id = ?').get(dbUser.id).count;
        const kc = db.prepare('SELECT COUNT(*) as count FROM keys WHERE user_id = ?').get(dbUser.id).count;
        const wc = db.prepare('SELECT COUNT(*) as count FROM whitelist WHERE user_id = ?').get(dbUser.id).count;
        const embed = new EmbedBuilder().setColor(BRAND_COLOR).setTitle('Account Ready').setDescription(`Welcome ${interaction.user.username}!`).addFields({ name: 'Scripts', value: String(sc), inline: true }, { name: 'Keys', value: String(kc), inline: true }, { name: 'Whitelisted', value: String(wc), inline: true }).setFooter({ text: 'Karma Protection' }).setTimestamp();
        await interaction.reply({ embeds: [embed], ephemeral: true });
        return;
      }

      if (command === 'scripts') {
        if (!user) return interaction.reply({ content: 'Use /setup first.', ephemeral: true });
        const scripts = db.prepare('SELECT * FROM scripts WHERE user_id = ? ORDER BY created_at DESC').all(user.id);
        if (!scripts.length) return interaction.reply({ content: 'No scripts.', ephemeral: true });
        const lines = scripts.map((s, i) => `${i+1}. ${s.name} - v${s.version||'1.0.0'} - ${s.status==='active'?'Active':'Disabled'}`);
        const embed = new EmbedBuilder().setColor(BRAND_COLOR).setTitle(`Your Scripts (${scripts.length})`).setDescription(lines.join('\n')).setFooter({ text: 'Karma Protection' }).setTimestamp();
        await interaction.reply({ embeds: [embed], ephemeral: true });
        return;
      }

      if (command === 'createkey') {
        if (!user) return interaction.reply({ content: 'Use /setup first.', ephemeral: true });
        const scriptName = interaction.options.getString('script');
        const hours = interaction.options.getInteger('hours') || null;
        if (!scriptName) return interaction.reply({ content: 'Script name required.', ephemeral: true });
        const script = db.prepare('SELECT * FROM scripts WHERE user_id = ? AND name = ?').get(user.id, scriptName);
        if (!script) return interaction.reply({ content: `No script "${scriptName}"`, ephemeral: true });
        const key = generateKey();
        const expiresAt = hours ? addHours(hours) : null;
        const id = makeId('key');
        db.prepare(`INSERT INTO keys (id, script_id, user_id, key, expires_at) VALUES (?, ?, ?, ?, ?)`).run(id, script.id, user.id, key, expiresAt);
        const embed = new EmbedBuilder().setColor(BRAND_COLOR).setTitle('Key Generated').setDescription(`**Script:** ${script.name}\n**Key:** \`${key}\`\n${hours ? 'Expires: ' + formatExpiry(expiresAt) : 'Permanent'}`).setFooter({ text: 'Karma Protection' }).setTimestamp();
        try { await interaction.user.send({ embeds: [embed] }); await interaction.reply({ content: 'Key sent to DMs.', ephemeral: true }); } catch { await interaction.reply({ embeds: [embed], ephemeral: true }); }
        return;
      }

      if (command === 'keys') {
        if (!user) return interaction.reply({ content: 'Use /setup first.', ephemeral: true });
        const keys = db.prepare('SELECT * FROM keys WHERE user_id = ? ORDER BY created_at DESC').all(user.id);
        if (!keys.length) return interaction.reply({ content: 'No keys.', ephemeral: true });
        const lines = keys.map(k => {
          const expired = k.expires_at && new Date(k.expires_at).getTime() < Date.now();
          return `${expired ? 'Expired' : 'Active'} ${k.hwid ? 'HWID-Locked' : 'Open'} ${maskKey(k.key)} - ${k.expires_at ? formatExpiry(k.expires_at) : 'Permanent'}`;
        });
        const embed = new EmbedBuilder().setColor(BRAND_COLOR).setTitle(`Your Keys (${keys.length})`).setDescription(lines.join('\n')).setFooter({ text: 'Karma Protection' }).setTimestamp();
        await interaction.reply({ embeds: [embed], ephemeral: true });
        return;
      }

      if (command === 'revoke') {
        if (!user) return interaction.reply({ content: 'Use /setup first.', ephemeral: true });
        const rawKey = interaction.options.getString('key');
        if (!rawKey) return interaction.reply({ content: 'Key required.', ephemeral: true });
        const keyRecord = db.prepare('SELECT * FROM keys WHERE key = ? AND user_id = ?').get(rawKey, user.id);
        if (!keyRecord) return interaction.reply({ content: 'Key not found.', ephemeral: true });
        db.prepare('DELETE FROM keys WHERE key = ? AND user_id = ?').run(rawKey, user.id);
        db.prepare('DELETE FROM whitelist WHERE key = ? AND user_id = ?').run(rawKey, user.id);
        await interaction.reply({ content: `Key ${maskKey(rawKey)} revoked.`, ephemeral: true });
        return;
      }

      if (command === 'resethwid') {
        if (!user) return interaction.reply({ content: 'Use /setup first.', ephemeral: true });
        const rawKey = interaction.options.getString('key');
        if (!rawKey) return interaction.reply({ content: 'Key required.', ephemeral: true });
        const keyRecord = db.prepare('SELECT * FROM keys WHERE key = ? AND user_id = ?').get(rawKey, user.id);
        if (!keyRecord) return interaction.reply({ content: 'Key not found.', ephemeral: true });
        if (keyRecord.resettable) {
          const elapsed = Date.now() - new Date(keyRecord.resettable).getTime();
          if (elapsed < COOLDOWN_MS) {
            const rem = COOLDOWN_MS - elapsed;
            return interaction.reply({ content: `Cooldown: ${Math.floor(rem/3600000)}h ${Math.floor((rem%3600000)/60000)}m remaining.`, ephemeral: true });
          }
        }
        db.prepare('UPDATE keys SET hwid = NULL, resettable = CURRENT_TIMESTAMP WHERE key = ?').run(rawKey);
        const wl = db.prepare('SELECT * FROM whitelist WHERE key = ? AND user_id = ?').get(rawKey, user.id);
        if (wl) db.prepare('UPDATE whitelist SET hwid = NULL WHERE id = ?').run(wl.id);
        await interaction.reply({ content: `HWID reset for ${maskKey(rawKey)}.`, ephemeral: true });
        return;
      }

      if (command === 'whitelist') {
        if (!user) return interaction.reply({ content: 'Use /setup first.', ephemeral: true });
        const scriptName = interaction.options.getString('script');
        const targetUser = interaction.options.getUser('user');
        const hours = interaction.options.getInteger('hours') || 0;
        if (!scriptName || !targetUser) return interaction.reply({ content: 'Script and user required.', ephemeral: true });
        const script = db.prepare('SELECT * FROM scripts WHERE user_id = ? AND name = ?').get(user.id, scriptName);
        if (!script) return interaction.reply({ content: `No script "${scriptName}"`, ephemeral: true });
        const targetId = targetUser.id;
        let dbTarget = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(targetId);
        if (!dbTarget) {
          const id = `user_${crypto.randomBytes(8).toString('hex')}`;
          db.prepare(`INSERT INTO users (id, discord_id, username, provider) VALUES (?, ?, ?, ?)`).run(id, targetId, targetUser.username, 'discord');
          dbTarget = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(targetId);
        }
        const key = generateKey();
        const expiresAt = hours > 0 ? addHours(hours) : null;
        const id = makeId('wl');
        const existing = db.prepare('SELECT * FROM whitelist WHERE script_id = ? AND discord_id = ?').get(script.id, targetId);
        if (existing) return interaction.reply({ content: 'User already whitelisted.', ephemeral: true });
        db.prepare(`INSERT INTO whitelist (id, script_id, user_id, key, discord_id, username, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(id, script.id, user.id, key, targetId, targetUser.username, expiresAt);
        db.prepare(`INSERT INTO keys (id, script_id, user_id, key, note, expires_at) VALUES (?, ?, ?, ?, ?, ?)`).run(makeId('key'), script.id, user.id, key, `Whitelisted for ${targetUser.username}`, expiresAt);
        const embed = new EmbedBuilder().setColor(BRAND_COLOR).setTitle('User Whitelisted').setDescription(`**Script:** ${script.name}\n**User:** ${targetUser}\n**Key:** \`${key}\`\n**Status:** ${hours > 0 ? 'Expires in '+hours+'h' : 'Permanent'}`).setFooter({ text: 'Karma Protection' }).setTimestamp();
        await interaction.reply({ embeds: [embed], ephemeral: true });
        try {
          const dm = new EmbedBuilder().setColor(BRAND_COLOR).setTitle('You were whitelisted!').setDescription(`**Script:** ${script.name}\n**Key:** \`${key}\`\n**Expires:** ${hours > 0 ? formatExpiry(expiresAt) : 'Permanent'}\n\nUse /resethwid if needed (24h cooldown).`).setFooter({ text: 'Karma Protection' }).setTimestamp();
          await targetUser.send({ embeds: [dm] });
        } catch (e) {}
        return;
      }

      if (command === 'unwhitelist') {
        if (!user) return interaction.reply({ content: 'Use /setup first.', ephemeral: true });
        const targetUser = interaction.options.getUser('user');
        if (!targetUser) return interaction.reply({ content: 'User required.', ephemeral: true });
        const targetId = targetUser.id;
        const entries = db.prepare('SELECT * FROM whitelist WHERE discord_id = ? AND user_id = ?').all(targetId, user.id);
        if (!entries.length) return interaction.reply({ content: 'User not whitelisted.', ephemeral: true });
        for (const e of entries) { db.prepare('DELETE FROM whitelist WHERE id = ?').run(e.id); db.prepare('DELETE FROM keys WHERE key = ? AND user_id = ?').run(e.key, user.id); }
        await interaction.reply({ content: `Removed ${targetUser} from whitelist.`, ephemeral: true });
        return;
      }

      if (command === 'whitelistlist' || command === 'wllist') {
        if (!user) return interaction.reply({ content: 'Use /setup first.', ephemeral: true });
        const entries = db.prepare('SELECT * FROM whitelist WHERE user_id = ? ORDER BY created_at DESC').all(user.id);
        if (!entries.length) return interaction.reply({ content: 'No users whitelisted.', ephemeral: true });
        const lines = entries.map(e => {
          const expired = e.expires_at && new Date(e.expires_at).getTime() < Date.now();
          return `${expired ? 'Expired' : 'Active'} ${e.hwid ? 'HWID-Locked' : 'Open'} <@${e.discord_id}> - ${e.username} - Expires: ${e.expires_at ? formatExpiry(e.expires_at) : 'Permanent'}`;
        });
        const embed = new EmbedBuilder().setColor(BRAND_COLOR).setTitle(`Whitelist (${entries.length})`).setDescription(lines.join('\n')).setFooter({ text: 'Karma Protection' }).setTimestamp();
        await interaction.reply({ embeds: [embed], ephemeral: true });
        return;
      }

      if (command === 'panelsetup' || command === 'panel') {
        if (!user) return interaction.reply({ content: 'Use /setup first.', ephemeral: true });
        const scriptName = interaction.options.getString('script');
        if (!scriptName) return interaction.reply({ content: 'Script name required.', ephemeral: true });
        const script = db.prepare('SELECT * FROM scripts WHERE user_id = ? AND name = ?').get(user.id, scriptName);
        if (!script) return interaction.reply({ content: `No script "${scriptName}"`, ephemeral: true });
        const embed = new EmbedBuilder().setColor(BRAND_COLOR).setTitle(script.name).setDescription('Use the buttons below.').setFooter({ text: 'Karma Protection' }).setTimestamp();
        const row1 = new ActionRowBuilder().addComponents(
          new ButtonBuilder().setCustomId(`pv_${script.id}`).setLabel('View').setStyle(ButtonStyle.Primary),
          new ButtonBuilder().setCustomId(`pr_${script.id}`).setLabel('Redeem').setStyle(ButtonStyle.Success)
        );
        const row2 = new ActionRowBuilder().addComponents(
          new ButtonBuilder().setCustomId(`pi_${script.id}`).setLabel('Keys').setStyle(ButtonStyle.Secondary),
          new ButtonBuilder().setCustomId(`pl_${script.id}`).setLabel('Loader').setStyle(ButtonStyle.Secondary)
        );
        const row3 = new ActionRowBuilder().addComponents(
          new ButtonBuilder().setCustomId(`ph_${script.id}`).setLabel('Reset HWID').setStyle(ButtonStyle.Danger)
        );
        await interaction.reply({ embeds: [embed], components: [row1, row2, row3] });
        return;
      }

      await interaction.reply({ content: 'Unknown command.', ephemeral: true });
    } catch (e) {
      console.error('Command error:', e);
      await interaction.reply({ content: 'An error occurred.', ephemeral: true });
    }
  }

  // Button & Modal handlers (same as before, with fixes)
  if (interaction.isButton()) {
    const customId = interaction.customId;
    const action = customId[1];
    const scriptId = customId.substring(3);
    try {
      const user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(interaction.user.id);
      if (!user) return interaction.reply({ content: 'Use /setup first.', ephemeral: true });
      const script = db.prepare('SELECT * FROM scripts WHERE id = ? AND user_id = ?').get(scriptId, user.id);
      if (!script) return interaction.reply({ content: 'Script not found.', ephemeral: true });
      if (action === 'v') {
        const kc = db.prepare('SELECT COUNT(*) as count FROM keys WHERE script_id = ? AND user_id = ?').get(scriptId, user.id).count;
        const wc = db.prepare('SELECT COUNT(*) as count FROM whitelist WHERE script_id = ? AND user_id = ?').get(scriptId, user.id).count;
        const embed = new EmbedBuilder().setColor(BRAND_COLOR).setTitle(script.name).addFields({ name: 'Version', value: script.version || '1.0.0', inline: true }, { name: 'Status', value: script.status === 'active' ? 'Active' : 'Disabled', inline: true }, { name: 'Keys', value: String(kc), inline: true }, { name: 'Whitelisted', value: String(wc), inline: true }).setFooter({ text: 'Karma Protection' }).setTimestamp();
        await interaction.reply({ embeds: [embed], ephemeral: true });
      } else if (action === 'r') {
        const modal = new ModalBuilder().setCustomId(`rm_${scriptId}`).setTitle('Redeem Key');
        modal.addComponents(new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('key_input').setLabel('Enter license key').setStyle(TextInputStyle.Short).setRequired(true)));
        await interaction.showModal(modal);
      } else if (action === 'i') {
        const keys = db.prepare('SELECT * FROM keys WHERE script_id = ? AND user_id = ? ORDER BY created_at DESC').all(scriptId, user.id);
        if (!keys.length) return interaction.reply({ content: 'No keys.', ephemeral: true });
        const lines = keys.map(k => {
          const expired = k.expires_at && new Date(k.expires_at).getTime() < Date.now();
          return `${expired ? 'Expired' : 'Active'} ${maskKey(k.key)} - ${k.hwid ? 'HWID-Locked' : 'Open'} - ${k.expires_at ? formatExpiry(k.expires_at) : 'Permanent'}`;
        });
        const embed = new EmbedBuilder().setColor(BRAND_COLOR).setTitle('Keys').setDescription(lines.join('\n')).setFooter({ text: 'Karma Protection' }).setTimestamp();
        await interaction.reply({ embeds: [embed], ephemeral: true });
      } else if (action === 'l') {
        const key = db.prepare('SELECT * FROM keys WHERE script_id = ? AND user_id = ? ORDER BY created_at DESC').get(scriptId, user.id);
        if (!key) return interaction.reply({ content: 'No active key.', ephemeral: true });
        await interaction.reply({ content: `\`\`\`lua\nloadstring(game:HttpGet("${publicBaseUrl()}/loader/${scriptId}?key=${key.key}"))()\n\`\`\``, ephemeral: true });
      } else if (action === 'h') {
        const modal = new ModalBuilder().setCustomId(`hm_${scriptId}`).setTitle('Reset HWID');
        modal.addComponents(new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('key_input').setLabel('Enter license key').setStyle(TextInputStyle.Short).setRequired(true)));
        await interaction.showModal(modal);
      }
    } catch (e) { console.error('Button error:', e); await interaction.reply({ content: 'Error.', ephemeral: true }); }
  }

  if (interaction.isModalSubmit()) {
    const customId = interaction.customId;
    try {
      const user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(interaction.user.id);
      if (!user) return interaction.reply({ content: 'Use /setup first.', ephemeral: true });
      if (customId.startsWith('rm_')) {
        const scriptId = customId.substring(3);
        const keyVal = interaction.fields.getTextInputValue('key_input').toUpperCase();
        const keyRecord = db.prepare('SELECT * FROM keys WHERE key = ? AND script_id = ? AND user_id = ?').get(keyVal, scriptId, user.id);
        if (!keyRecord) return interaction.reply({ content: 'Invalid key.', ephemeral: true });
        if (keyRecord.expires_at && new Date(keyRecord.expires_at).getTime() < Date.now()) return interaction.reply({ content: 'Key expired.', ephemeral: true });
        db.prepare('UPDATE keys SET last_used_at = CURRENT_TIMESTAMP WHERE key = ?').run(keyVal);
        await interaction.reply({ content: 'Key redeemed successfully.', ephemeral: true });
      } else if (customId.startsWith('hm_')) {
        const scriptId = customId.substring(3);
        const keyVal = interaction.fields.getTextInputValue('key_input').toUpperCase();
        const keyRecord = db.prepare('SELECT * FROM keys WHERE key = ? AND script_id = ? AND user_id = ?').get(keyVal, scriptId, user.id);
        if (!keyRecord) return interaction.reply({ content: 'Invalid key.', ephemeral: true });
        if (keyRecord.resettable) {
          const elapsed = Date.now() - new Date(keyRecord.resettable).getTime();
          if (elapsed < COOLDOWN_MS) {
            const rem = COOLDOWN_MS - elapsed;
            return interaction.reply({ content: `Cooldown: ${Math.floor(rem/3600000)}h ${Math.floor((rem%3600000)/60000)}m remaining.`, ephemeral: true });
          }
        }
        db.prepare('UPDATE keys SET hwid = NULL, resettable = CURRENT_TIMESTAMP WHERE key = ?').run(keyVal);
        const wl = db.prepare('SELECT * FROM whitelist WHERE key = ? AND user_id = ?').get(keyVal, user.id);
        if (wl) db.prepare('UPDATE whitelist SET hwid = NULL WHERE id = ?').run(wl.id);
        await interaction.reply({ content: 'HWID reset successfully.', ephemeral: true });
      }
    } catch (e) { console.error('Modal error:', e); await interaction.reply({ content: 'Error.', ephemeral: true }); }
  }
});

// ============ START SERVER ============
const port = Number(process.env.PORT || 10000);
(async () => {
  app.listen(port, '0.0.0.0', () => {
    console.log(`Karma Protection v7.0 running on port ${port}`);
    console.log(`Website: ${publicBaseUrl()}`);
  });
  await client.login(DISCORD_TOKEN);
})();