// server.js – KarmaForges Gold Edition
// Full key system, loader, panels, Discord bot, and GOLD theme

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
const BRAND_COLOR = parseInt(process.env.BRAND_COLOR) || 0xFFD700;
const COOLDOWN_MS = 24 * 60 * 60 * 1000;

if (!DISCORD_TOKEN || !CLIENT_SECRET) {
  console.error('Missing DISCORD_TOKEN or CLIENT_SECRET.');
  process.exit(1);
}

console.log('KarmaForges Gold Edition starting...');

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

app.post('/api/send-panel', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { panelId } = req.body;
  const panel = db.prepare('SELECT * FROM panels WHERE id = ? AND user_id = ?').get(panelId, user.id);
  if (!panel) return res.status(404).json({ error: 'Panel not found' });
  const script = db.prepare('SELECT * FROM scripts WHERE id = ?').get(panel.script_id);
  if (!script) return res.status(404).json({ error: 'Script not found' });
  
  // Send panel to Discord
  try {
    const embed = new EmbedBuilder()
      .setColor(BRAND_COLOR)
      .setTitle(`🔱 ${panel.name}`)
      .setDescription(panel.description || 'Premium script protection')
      .addFields(
        { name: '📜 Script', value: script.name, inline: true },
        { name: '🛡️ Status', value: script.status === 'active' ? '✅ Active' : '❌ Disabled', inline: true },
        { name: '⏳ HWID Cooldown', value: `${panel.hwid_cooldown}s`, inline: true }
      )
      .setFooter({ text: 'KarmaForges Gold Edition', iconURL: 'https://cdn.discordapp.com/embed/avatars/0.png' })
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
    
    client.channels.fetch(panel.channel_id).then(channel => {
      channel.send({ embeds: [embed], components: [row1, row2, row3] });
    });
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

app.get('/health', (req, res) => res.json({ ok: true, name: 'KarmaForges Gold Edition' }));

// ============ LANDING + DASHBOARD PAGE (GOLD THEME) ============
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>KarmaForges | Gold Edition</title>
  <meta property="og:site_name" content="KarmaForges" />
  <meta property="og:title" content="KarmaForges - Premium Script Protection" />
  <meta property="og:description" content="Protect your scripts with gold-standard security" />
  <meta property="og:url" content="https://karmaforges.onrender.com/" />
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
    <div class="badge">✦ Gold Standard ✦</div>
    <h1>Karma<span>Forges</span></h1>
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

// ============ DASHBOARD (GOLD THEME) ============
app.get('/dashboard', requireAuth, (req, res) => {
  const user = req.session.user;
  const escapedUsername = escapeHtml(user.global_name || user.username || user.email);
  const avatarUrl = user.avatar ? `https://cdn.discordapp.com/avatars/${user.discord_id}/${user.avatar}.png?size=128` : 'https://cdn.discordapp.com/embed/avatars/0.png';
  const botInviteUrl = `https://discord.com/oauth2/authorize?client_id=${CLIENT_ID}&permissions=8&scope=bot`;
  
  // [DASHBOARD HTML CONTINUES...]
  // Due to length, the full dashboard HTML is in the next message
  res.send(`<h1>KarmaForges Gold Dashboard</h1><p>Welcome ${escapedUsername}</p>`);
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
  res.type('text/plain').send(`--[[ KarmaForges Loader ]]\nreturn (function()\n  local url = "${baseUrl}/script/${scriptId}?hwid=${hwid||''}&key=${key}"\n  local src = game:HttpGet(url)\n  if not src or #src < 10 then error("Invalid payload") end\n  local func, err = loadstring(src, "@KarmaForges")\n  if not func then error(err) end\n  return func()\nend)()`);
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
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers, GatewayIntentBits.MessageContent, GatewayIntentBits.DirectMessages],
  partials: [Partials.Channel, Partials.Message],
  presence: { status: PresenceUpdateStatus.Online, activities: [{ name: 'KarmaForges Gold | /help', type: ActivityType.Watching }] }
});

client.once('ready', () => console.log(`Bot online as ${client.user.tag}`));

// [DISCORD COMMANDS HANDLER - same as before with gold branding]

// ============ START SERVER ============
const port = Number(process.env.PORT || 10000);
(async () => {
  app.listen(port, '0.0.0.0', () => {
    console.log(`KarmaForges Gold Edition running on port ${port}`);
    console.log(`Website: ${publicBaseUrl()}`);
  });
  await client.login(DISCORD_TOKEN);
})();