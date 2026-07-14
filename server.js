// server.js – KarmaForges v7.0 (complete with embedded index.html)

const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcrypt');
const compression = require('compression');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
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

require('dotenv').config();

// ============ ENVIRONMENT ============
const DISCORD_TOKEN = process.env.DISCORD_TOKEN;
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const GUILD_ID = process.env.GUILD_ID;
const DATABASE_PATH = process.env.DATABASE_PATH || './data.sqlite';
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || 'https://karmaforges.onrender.com';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const OWNER_EMAILS = (process.env.OWNER_EMAILS || '').split(',').map(e => e.trim()).filter(Boolean);
const OWNER_USERNAMES = (process.env.OWNER_USERNAMES || '').split(',').map(u => u.trim()).filter(Boolean);
const MAX_SCRIPTS = parseInt(process.env.MAX_SCRIPTS_PER_USER) || 20;
const BRAND_COLOR = parseInt(process.env.BRAND_COLOR) || 0x6366f1;
const PREFIX = process.env.PREFIX || '/';
const COOLDOWN_HWID_RESET = 24 * 60 * 60 * 1000;

if (!DISCORD_TOKEN || !CLIENT_SECRET) {
  console.error('Missing DISCORD_TOKEN or CLIENT_SECRET.');
  process.exit(1);
}

console.log('🐱 KarmaForges v7.0 starting...');
console.log(`Database: ${DATABASE_PATH}`);
console.log(`Base URL: ${PUBLIC_BASE_URL}`);

// ============ DATABASE ============
const db = new Database(DATABASE_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  discord_id TEXT UNIQUE,
  username TEXT UNIQUE,
  email TEXT UNIQUE,
  password_hash TEXT,
  password_salt TEXT,
  avatar TEXT,
  credits INTEGER DEFAULT 0,
  is_owner INTEGER DEFAULT 0,
  referral_code TEXT UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scripts (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  filename TEXT,
  code TEXT,
  obfuscated_code TEXT,
  version TEXT DEFAULT '1.0.0',
  status TEXT DEFAULT 'active',
  ffa_mode INTEGER DEFAULT 0,
  compress_mode INTEGER DEFAULT 0,
  obfuscation_layers TEXT DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS keys (
  id TEXT PRIMARY KEY,
  script_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  panel_id TEXT,
  key TEXT UNIQUE NOT NULL,
  hwid TEXT,
  note TEXT,
  expires_at TEXT,
  resettable_at TEXT,
  used_count INTEGER DEFAULT 0,
  max_uses INTEGER DEFAULT 1,
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

CREATE TABLE IF NOT EXISTS referrals (
  id TEXT PRIMARY KEY,
  referrer_id TEXT NOT NULL,
  referred_id TEXT UNIQUE NOT NULL,
  credits_awarded INTEGER DEFAULT 10,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(referrer_id) REFERENCES users(id),
  FOREIGN KEY(referred_id) REFERENCES users(id)
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

CREATE TABLE IF NOT EXISTS obfuscation_logs (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  script_id TEXT NOT NULL,
  layers TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(script_id) REFERENCES scripts(id)
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

CREATE INDEX IF NOT EXISTS idx_keys_key ON keys(key);
CREATE INDEX IF NOT EXISTS idx_keys_script_id ON keys(script_id);
CREATE INDEX IF NOT EXISTS idx_scripts_user_id ON scripts(user_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
`);

// ============ HELPER FUNCTIONS ============
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

function generateReferralCode() {
  return 'REF-' + crypto.randomBytes(4).toString('hex').toUpperCase();
}

function maskKey(key) { return key ? 'KARMA-****-****-' + key.slice(-4).toUpperCase() : 'Invalid'; }
function addHours(hours) { return (hours && hours > 0) ? new Date(Date.now() + hours * 3600000).toISOString() : null; }
function publicBaseUrl() { return PUBLIC_BASE_URL.replace(/\/$/, ''); }

function escapeHtml(s) {
  return String(s)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function getSessionUser(req) { return req.session.user || null; }

function requireAuth(req, res, next) {
  if (req.session.user) return next();
  res.redirect('/');
}

function formatExpiry(e) {
  return e ? new Date(e).toLocaleDateString() + ' ' + new Date(e).toLocaleTimeString() : 'Permanent';
}

function isOwner(user) {
  if (!user) return false;
  const emailMatch = user.email && OWNER_EMAILS.includes(user.email);
  const usernameMatch = user.username && OWNER_USERNAMES.includes(user.username);
  return emailMatch || usernameMatch || user.is_owner === 1;
}

function hashPassword(password) {
  return bcrypt.hashSync(password, 10);
}

function verifyPassword(password, hash) {
  return bcrypt.compareSync(password, hash);
}

// ============ OBFUSCATION ENGINE ============
class KarmaObfuscator {
  static XOR_KEYS = [0x5A, 0x3F, 0x9C, 0x2E, 0x7D, 0xB1, 0x4E, 0x8F, 0x6C, 0xD3, 0xE7, 0x1B, 0xF4, 0x82, 0x5B, 0x0A];
  static BASE92_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/~`';
  static VM_OPS = ['ADD', 'SUB', 'XOR', 'SHL', 'SHR', 'LOAD', 'STORE', 'JMP', 'CALL', 'RET'];

  static xorLayer(data) {
    let result = '';
    for (let i = 0; i < data.length; i++) {
      const key = this.XOR_KEYS[i % this.XOR_KEYS.length];
      result += String.fromCharCode(data.charCodeAt(i) ^ key);
    }
    return result;
  }

  static base92Encode(data) {
    let value = 0, bits = 0, output = [];
    for (let i = 0; i < data.length; i++) {
      value = (value << 8) | data.charCodeAt(i);
      bits += 8;
      while (bits >= 14) {
        const idx = (value >> (bits - 14)) & 0x3FFF;
        output.push(this.BASE92_ALPHABET[idx % 92]);
        output.push(this.BASE92_ALPHABET[Math.floor(idx / 92)]);
        bits -= 14;
        value &= (1 << bits) - 1;
      }
    }
    if (bits > 0) {
      const idx = value << (14 - bits);
      output.push(this.BASE92_ALPHABET[idx % 92]);
      if (bits > 7) output.push(this.BASE92_ALPHABET[Math.floor(idx / 92)]);
    }
    return output.join('');
  }

  static vmLayer(code) {
    const instructions = [];
    for (let i = 0; i < code.length; i++) {
      const op = this.VM_OPS[i % this.VM_OPS.length];
      const val = code.charCodeAt(i) ^ this.XOR_KEYS[i % this.XOR_KEYS.length];
      instructions.push({ op, val });
    }
    return JSON.stringify(instructions);
  }

  static antiDeobfuscateTrap() {
    return `--[[ Anti-Deobfuscation Trap ]]
local function checkEnvironment()
    local env = getfenv and getfenv() or _G
    if not env.game or not env.game:GetService then
        print("skidder")
        return false
    end
    return true
end
if not checkEnvironment() then return end
`;
  }

  static selfModifyingLoader(bytecode) {
    const xorKeysStr = this.XOR_KEYS.join(',');
    return `--[[ KarmaForges Self-Modifying Loader v7.0 ]]
local bytecode = "${bytecode}"
local xorKeys = {${xorKeysStr}}
local function decode(bc)
    local decoded = ""
    for i = 1, #bc, 2 do
        local byte = tonumber(bc:sub(i, i+1), 16)
        if byte then
            local key = xorKeys[(i % #xorKeys) + 1]
            decoded = decoded .. string.char(byte ~ key)
        end
    end
    return decoded
end
local decoded = decode(bytecode)
local fn, err = loadstring(decoded, "@KarmaVM")
if not fn then error(err) end
fn()
`;
  }

  static obfuscate(code, userId, layers = null) {
    if (!layers) {
      layers = { xor: true, base92: true, vm: true, trap: true };
    }

    let result = code;

    if (layers.trap !== false) {
      result = this.antiDeobfuscateTrap() + '\n' + result;
    }

    if (layers.xor !== false) {
      result = this.xorLayer(result);
    }

    if (layers.base92 !== false) {
      result = this.base92Encode(result);
    }

    let vmBytecode = result;
    if (layers.vm !== false) {
      vmBytecode = this.vmLayer(result);
    }

    const final = this.selfModifyingLoader(vmBytecode);

    return {
      code: final,
      layers: layers,
      size: final.length,
      originalSize: code.length
    };
  }
}

// ============ EXPRESS APP ============
const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:", "https://cdn.discordapp.com", "https://ui-avatars.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'"],
    },
  },
}));
app.use(compression());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests, please try again later.',
});
app.use('/api/', limiter);

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: PUBLIC_BASE_URL.startsWith('https'),
    maxAge: 7 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    sameSite: 'lax'
  }
}));

// ============ MULTER CONFIGURATION ============
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const user = req.session.user;
    if (!user) {
      return cb(new Error('Not authenticated'), null);
    }
    const userDir = path.join(__dirname, 'public/uploads', user.id);
    if (!fs.existsSync(userDir)) {
      fs.mkdirSync(userDir, { recursive: true });
    }
    cb(null, userDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['.lua', '.txt', '.luac', '.js', '.py'];
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, allowed.includes(ext));
  }
});

// ============ API ROUTES ============

app.get('/health', (req, res) => {
  res.json({ ok: true, name: 'KarmaForges v7.0', uptime: process.uptime() });
});

// ============ DISCORD AUTH ============

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
    
    let dbUser = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(user.id);
    if (!dbUser) {
      const id = makeId('user');
      const referralCode = generateReferralCode();
      db.prepare(
        `INSERT INTO users (id, discord_id, username, avatar, referral_code)
         VALUES (?, ?, ?, ?, ?)`
      ).run(id, user.id, user.username, user.avatar || '', referralCode);
      dbUser = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(user.id);
    } else {
      db.prepare(
        'UPDATE users SET username = ?, avatar = ?, updated_at = CURRENT_TIMESTAMP WHERE discord_id = ?'
      ).run(user.username, user.avatar || '', user.id);
    }

    const redirectUrl = `${publicBaseUrl()}/dashboard#user=${encodeURIComponent(user.username)}&id=${user.id}&avatar=${user.avatar || ''}`;
    res.redirect(redirectUrl);
  } catch (e) {
    console.error('Auth error:', e);
    res.status(500).send('Authentication failed');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// ============ DATA API ============

app.get('/api/data', requireAuth, (req, res) => {
  const user = req.session.user;
  const scripts = db.prepare('SELECT * FROM scripts WHERE user_id = ? ORDER BY created_at DESC').all(user.id);
  const panels = db.prepare('SELECT * FROM panels WHERE user_id = ? ORDER BY created_at DESC').all(user.id);
  const keys = db.prepare(
    `SELECT k.*, u.username as claimed_tag 
     FROM keys k 
     LEFT JOIN users u ON k.claimed_by = u.id 
     WHERE k.user_id = ? 
     ORDER BY k.created_at DESC`
  ).all(user.id);
  const banned = db.prepare('SELECT * FROM banned_hwids ORDER BY created_at DESC').all();
  const apiKeys = db.prepare('SELECT id, key, name, created_at, last_used_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC').all(user.id);
  res.json({ scripts, panels, keys, bannedHWIDs: banned, apiKeys, serverTime: Date.now() });
});

// ============ SCRIPT MANAGEMENT ============

app.post('/api/create-script', requireAuth, (req, res) => {
  const user = req.session.user;
  const { name, code, compressMode } = req.body;
  if (!name || !code) return res.status(400).json({ error: 'Missing name or code' });

  const count = db.prepare('SELECT COUNT(*) as total FROM scripts WHERE user_id = ?').get(user.id);
  if (count.total >= MAX_SCRIPTS) {
    return res.status(400).json({ error: `Maximum ${MAX_SCRIPTS} scripts reached` });
  }

  const id = makeId('script');
  const obfResult = KarmaObfuscator.obfuscate(code, user.id);
  const obfuscatedCode = obfResult.code;

  db.prepare(
    `INSERT INTO scripts (id, user_id, name, code, obfuscated_code, version, status, compress_mode, obfuscation_layers)
     VALUES (?, ?, ?, ?, ?, '1.0.0', 'active', ?, ?)`
  ).run(id, user.id, name, code, obfuscatedCode, compressMode ? 1 : 0, JSON.stringify(obfResult.layers));

  res.json({ success: true, id });
});

app.post('/api/update-script', requireAuth, (req, res) => {
  const user = req.session.user;
  const { id, name, code, compressMode } = req.body;
  if (!id || !name || !code) return res.status(400).json({ error: 'Missing fields' });

  const existing = db.prepare('SELECT * FROM scripts WHERE id = ? AND user_id = ?').get(id, user.id);
  if (!existing) return res.status(404).json({ error: 'Script not found' });

  const obfResult = KarmaObfuscator.obfuscate(code, user.id);
  const obfuscatedCode = obfResult.code;

  db.prepare(
    `UPDATE scripts 
     SET name = ?, code = ?, obfuscated_code = ?, compress_mode = ?, obfuscation_layers = ?, updated_at = CURRENT_TIMESTAMP 
     WHERE id = ? AND user_id = ?`
  ).run(name, code, obfuscatedCode, compressMode ? 1 : 0, JSON.stringify(obfResult.layers), id, user.id);

  res.json({ success: true });
});

app.get('/api/script/:id', requireAuth, (req, res) => {
  const user = req.session.user;
  const script = db.prepare('SELECT * FROM scripts WHERE id = ? AND user_id = ?').get(req.params.id, user.id);
  if (!script) return res.status(404).json({ error: 'Script not found' });
  res.json({ script });
});

app.put('/api/scripts/:id/toggle', requireAuth, (req, res) => {
  const user = req.session.user;
  const { id } = req.params;
  const script = db.prepare('SELECT * FROM scripts WHERE id = ? AND user_id = ?').get(id, user.id);
  if (!script) return res.status(404).json({ error: 'Script not found' });
  const newStatus = script.status === 'active' ? 'disabled' : 'active';
  db.prepare('UPDATE scripts SET status = ? WHERE id = ? AND user_id = ?').run(newStatus, id, user.id);
  res.json({ success: true, status: newStatus });
});

app.put('/api/scripts/:id/ffa', requireAuth, (req, res) => {
  const user = req.session.user;
  const { id } = req.params;
  const script = db.prepare('SELECT * FROM scripts WHERE id = ? AND user_id = ?').get(id, user.id);
  if (!script) return res.status(404).json({ error: 'Script not found' });
  const newFfa = script.ffa_mode ? 0 : 1;
  db.prepare('UPDATE scripts SET ffa_mode = ? WHERE id = ? AND user_id = ?').run(newFfa, id, user.id);
  res.json({ success: true, ffa_mode: newFfa });
});

app.post('/api/delete-script', requireAuth, (req, res) => {
  const user = req.session.user;
  const { id } = req.body;
  db.prepare('DELETE FROM scripts WHERE id = ? AND user_id = ?').run(id, user.id);
  res.json({ success: true });
});

// ============ PANEL MANAGEMENT ============

app.post('/api/create-panel', requireAuth, (req, res) => {
  const user = req.session.user;
  const { name, description, channelId, scriptId, hwidCooldown } = req.body;
  if (!name || !channelId || !scriptId) return res.status(400).json({ error: 'Missing fields' });

  const id = makeId('panel');
  db.prepare(
    `INSERT INTO panels (id, user_id, name, description, channel_id, script_id, hwid_cooldown)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(id, user.id, name, description || '', channelId, scriptId, hwidCooldown || 180);

  res.json({ success: true, id });
});

app.post('/api/update-panel', requireAuth, (req, res) => {
  const user = req.session.user;
  const { id, name, description, channelId, scriptId, hwidCooldown } = req.body;
  if (!id || !name || !channelId || !scriptId) return res.status(400).json({ error: 'Missing fields' });

  const existing = db.prepare('SELECT * FROM panels WHERE id = ? AND user_id = ?').get(id, user.id);
  if (!existing) return res.status(404).json({ error: 'Panel not found' });

  db.prepare(
    `UPDATE panels 
     SET name = ?, description = ?, channel_id = ?, script_id = ?, hwid_cooldown = ?, updated_at = CURRENT_TIMESTAMP 
     WHERE id = ? AND user_id = ?`
  ).run(name, description || '', channelId, scriptId, hwidCooldown || 180, id, user.id);

  res.json({ success: true });
});

app.post('/api/delete-panel', requireAuth, (req, res) => {
  const user = req.session.user;
  const { id } = req.body;
  db.prepare('DELETE FROM panels WHERE id = ? AND user_id = ?').run(id, user.id);
  res.json({ success: true });
});

app.post('/api/send-panel', requireAuth, (req, res) => {
  const user = req.session.user;
  const { panelId } = req.body;
  const panel = db.prepare('SELECT * FROM panels WHERE id = ? AND user_id = ?').get(panelId, user.id);
  if (!panel) return res.status(404).json({ error: 'Panel not found' });

  if (client.isReady()) {
    const channel = client.channels.cache.get(panel.channel_id);
    if (channel) {
      const embed = new EmbedBuilder()
        .setColor(BRAND_COLOR)
        .setTitle(panel.name)
        .setDescription(panel.description || 'Use the buttons below to manage your script.')
        .addFields({ name: 'Script ID', value: panel.script_id, inline: true })
        .setFooter({ text: 'KarmaForges v7.0' })
        .setTimestamp();

      const row1 = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId(`pv_${panel.script_id}`).setLabel('View Script').setStyle(ButtonStyle.Primary),
        new ButtonBuilder().setCustomId(`pr_${panel.script_id}`).setLabel('Redeem Key').setStyle(ButtonStyle.Success)
      );
      const row2 = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId(`pi_${panel.script_id}`).setLabel('Keys').setStyle(ButtonStyle.Secondary),
        new ButtonBuilder().setCustomId(`pl_${panel.script_id}`).setLabel('Loader').setStyle(ButtonStyle.Secondary)
      );
      const row3 = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId(`ph_${panel.script_id}`).setLabel('Reset HWID').setStyle(ButtonStyle.Danger)
      );

      channel.send({ embeds: [embed], components: [row1, row2, row3] });
      res.json({ success: true, message: 'Panel sent to Discord' });
    } else {
      res.status(400).json({ error: 'Channel not found. Check channel ID and bot permissions.' });
    }
  } else {
    res.status(503).json({ error: 'Discord bot is not ready' });
  }
});

// ============ KEY MANAGEMENT ============

app.post('/api/generate-key', requireAuth, (req, res) => {
  const user = req.session.user;
  const { durationHours, panelId, note } = req.body;

  if (!panelId) return res.status(400).json({ error: 'Panel ID required' });

  const panel = db.prepare('SELECT * FROM panels WHERE id = ? AND user_id = ?').get(panelId, user.id);
  if (!panel) return res.status(404).json({ error: 'Panel not found' });

  const key = generateKey();
  const expiresAt = durationHours > 0 ? addHours(durationHours) : null;
  const id = makeId('key');

  db.prepare(
    `INSERT INTO keys (id, script_id, panel_id, user_id, key, note, expires_at, max_uses)
     VALUES (?, ?, ?, ?, ?, ?, ?, 1)`
  ).run(id, panel.script_id, panelId, user.id, key, note || '', expiresAt);

  res.json({ success: true, key });
});

app.post('/api/delete-key', requireAuth, (req, res) => {
  const user = req.session.user;
  const { key } = req.body;
  db.prepare('DELETE FROM keys WHERE key = ? AND user_id = ?').run(key, user.id);
  res.json({ success: true });
});

app.post('/api/add-time-all', requireAuth, (req, res) => {
  const user = req.session.user;
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

app.post('/api/reset-hwid', requireAuth, (req, res) => {
  const user = req.session.user;
  const { key } = req.body;

  if (!key) return res.status(400).json({ error: 'Key required' });

  const keyRecord = db.prepare('SELECT * FROM keys WHERE key = ? AND user_id = ?').get(key, user.id);
  if (!keyRecord) return res.status(404).json({ error: 'Key not found' });

  if (keyRecord.resettable_at) {
    const lastReset = new Date(keyRecord.resettable_at).getTime();
    const elapsed = Date.now() - lastReset;
    if (elapsed < COOLDOWN_HWID_RESET) {
      const remaining = COOLDOWN_HWID_RESET - elapsed;
      const hours = Math.floor(remaining / 3600000);
      const minutes = Math.floor((remaining % 3600000) / 60000);
      return res.status(429).json({
        error: `Cooldown: ${hours}h ${minutes}m remaining`,
        remaining: remaining
      });
    }
  }

  db.prepare('UPDATE keys SET hwid = NULL, resettable_at = CURRENT_TIMESTAMP WHERE key = ?').run(key);
  res.json({ success: true, message: 'HWID reset successfully' });
});

// ============ HWID BAN MANAGEMENT ============

app.post('/api/ban-hwid', requireAuth, (req, res) => {
  const user = req.session.user;
  const { hwid } = req.body;
  if (!hwid) return res.status(400).json({ error: 'HWID required' });

  db.prepare('INSERT OR REPLACE INTO banned_hwids (hwid, banned_by) VALUES (?, ?)').run(hwid, user.id);
  res.json({ success: true });
});

app.post('/api/unban-hwid', requireAuth, (req, res) => {
  const user = req.session.user;
  const { hwid } = req.body;
  if (!hwid) return res.status(400).json({ error: 'HWID required' });

  db.prepare('DELETE FROM banned_hwids WHERE hwid = ?').run(hwid);
  res.json({ success: true });
});

// ============ LOADER ROUTES ============

app.get('/loader/:scriptId', (req, res) => {
  const { scriptId } = req.params;
  const { key, hwid } = req.query;

  const script = db.prepare('SELECT * FROM scripts WHERE id = ? AND status = "active"').get(scriptId);
  if (!script) {
    return res.status(404).type('text/plain').send('-- Script not found');
  }

  if (script.ffa_mode === 1) {
    const loader = `--[[ KarmaForges FFA Loader ]]\nloadstring(game:HttpGet("${publicBaseUrl()}/api/script/${scriptId}"))()`;
    return res.type('text/plain').send(loader);
  }

  if (!key) {
    return res.status(403).type('text/plain').send('-- Missing key');
  }

  const keyRecord = db.prepare('SELECT * FROM keys WHERE key = ? AND script_id = ?').get(key, scriptId);
  if (!keyRecord) {
    return res.status(403).type('text/plain').send('-- Invalid key');
  }

  if (keyRecord.expires_at && new Date(keyRecord.expires_at).getTime() < Date.now()) {
    return res.status(403).type('text/plain').send('-- Key expired');
  }

  if (keyRecord.max_uses > 0 && keyRecord.used_count >= keyRecord.max_uses) {
    return res.status(403).type('text/plain').send('-- Key already used maximum times');
  }

  if (hwid) {
    const banned = db.prepare('SELECT * FROM banned_hwids WHERE hwid = ?').get(hwid);
    if (banned) {
      return res.status(403).type('text/plain').send('-- HWID banned');
    }
  }

  if (hwid) {
    if (!keyRecord.hwid) {
      db.prepare('UPDATE keys SET hwid = ?, last_used_at = CURRENT_TIMESTAMP WHERE key = ?').run(hwid, key);
    } else if (keyRecord.hwid !== hwid) {
      return res.status(403).type('text/plain').send('-- HWID mismatch. Use /reset-hwid');
    }
  }

  db.prepare('UPDATE keys SET used_count = used_count + 1, last_used_at = CURRENT_TIMESTAMP WHERE key = ?').run(key);

  const loader = `--[[ KarmaForges Loader v7.0 ]]
return (function()
    local url = "${publicBaseUrl()}/api/script/${scriptId}"
    local key = "${key}"
    local hwid = "${hwid || ''}"
    local full_url = url .. "?key=" .. key .. "&hwid=" .. hwid
    local src = game:HttpGet(full_url)
    if not src or #src < 10 then error("Invalid payload") end
    local fn, err = loadstring(src, "@KarmaForges")
    if not fn then error(err) end
    return fn()
end)()
`;

  res.type('text/plain').send(loader);
});

app.get('/api/script/:scriptId', (req, res) => {
  const { scriptId } = req.params;
  const { key, hwid } = req.query;

  const script = db.prepare('SELECT * FROM scripts WHERE id = ? AND status = "active"').get(scriptId);
  if (!script) {
    return res.status(404).type('text/plain').send('-- Script not found');
  }

  if (script.ffa_mode === 1) {
    res.setHeader('Cache-Control', 'no-store');
    return res.type('text/plain').send(script.obfuscated_code || script.code || '-- Empty');
  }

  if (!key) {
    return res.status(403).type('text/plain').send('-- Missing key');
  }

  const keyRecord = db.prepare('SELECT * FROM keys WHERE key = ? AND script_id = ?').get(key, scriptId);
  if (!keyRecord) {
    return res.status(403).type('text/plain').send('-- Invalid key');
  }

  if (keyRecord.expires_at && new Date(keyRecord.expires_at).getTime() < Date.now()) {
    return res.status(403).type('text/plain').send('-- Key expired');
  }

  if (keyRecord.max_uses > 0 && keyRecord.used_count >= keyRecord.max_uses) {
    return res.status(403).type('text/plain').send('-- Key used maximum times');
  }

  if (hwid) {
    const banned = db.prepare('SELECT * FROM banned_hwids WHERE hwid = ?').get(hwid);
    if (banned) {
      return res.status(403).type('text/plain').send('-- HWID banned');
    }
  }

  if (hwid && keyRecord.hwid && keyRecord.hwid !== hwid) {
    return res.status(403).type('text/plain').send('-- HWID mismatch');
  }

  if (hwid && !keyRecord.hwid) {
    db.prepare('UPDATE keys SET hwid = ?, last_used_at = CURRENT_TIMESTAMP WHERE key = ?').run(hwid, key);
  }

  db.prepare('UPDATE keys SET used_count = used_count + 1, last_used_at = CURRENT_TIMESTAMP WHERE key = ?').run(key);

  res.setHeader('Cache-Control', 'no-store');
  res.type('text/plain').send(script.obfuscated_code || script.code || '-- Empty');
});

// ============ FRONTEND ROUTES ============

app.get('/', (req, res) => {
  res.send(indexHTML);
});

app.get('/dashboard', (req, res) => {
  res.send(indexHTML);
});

// ============ DISCORD BOT ============

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.DirectMessages
  ],
  partials: [Partials.Channel, Partials.Message],
  presence: {
    status: PresenceUpdateStatus.Online,
    activities: [{ name: 'KarmaForges | /help', type: ActivityType.Watching }]
  }
});

client.once('ready', () => {
  console.log(`🤖 Discord bot online as ${client.user.tag}`);
});

// ============ DISCORD COMMANDS ============

client.on('messageCreate', async (msg) => {
  if (msg.author.bot || !msg.content.startsWith(PREFIX)) return;

  const parts = msg.content.slice(PREFIX.length).trim().split(/\s+/);
  const cmd = parts.shift().toLowerCase();
  const args = parts;

  try {
    const user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(msg.author.id);

    if (cmd === 'help') {
      const embed = new EmbedBuilder()
        .setColor(BRAND_COLOR)
        .setTitle('🐱 KarmaForges – Commands')
        .setDescription([
          '**General**',
          `${PREFIX}setup – Create/load account`,
          `${PREFIX}scripts – List your scripts`,
          `${PREFIX}keys – List your keys`,
          '',
          '**Keys**',
          `${PREFIX}key <script_id> [hours] – Generate key`,
          `${PREFIX}reset-hwid <key> – Reset HWID (24h cooldown)`,
          '',
          '**Admin**',
          `${PREFIX}ban <hwid> – Ban HWID`,
          `${PREFIX}unban <hwid> – Unban HWID`
        ].join('\n'))
        .setFooter({ text: 'KarmaForges v7.0' })
        .setTimestamp();

      try {
        await msg.author.send({ embeds: [embed] });
        await msg.reply('📨 Check your DMs!');
      } catch {
        await msg.reply({ embeds: [embed] });
      }
      return;
    }

    if (cmd === 'setup') {
      let dbUser = user;
      if (!dbUser) {
        const id = makeId('user');
        const referralCode = generateReferralCode();
        db.prepare(
          `INSERT INTO users (id, discord_id, username, avatar, referral_code)
           VALUES (?, ?, ?, ?, ?)`
        ).run(id, msg.author.id, msg.author.username, msg.author.displayAvatarURL() || '', referralCode);
        dbUser = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(msg.author.id);
      }

      const sc = db.prepare('SELECT COUNT(*) as count FROM scripts WHERE user_id = ?').get(dbUser.id);
      const kc = db.prepare('SELECT COUNT(*) as count FROM keys WHERE user_id = ?').get(dbUser.id);

      const embed = new EmbedBuilder()
        .setColor(BRAND_COLOR)
        .setTitle('✅ Account Ready')
        .setDescription(`Welcome ${msg.author.username}!`)
        .addFields(
          { name: 'Scripts', value: String(sc.count), inline: true },
          { name: 'Keys', value: String(kc.count), inline: true },
          { name: 'Credits', value: String(dbUser.credits || 0), inline: true }
        )
        .setFooter({ text: 'KarmaForges' })
        .setTimestamp();

      await msg.reply({ embeds: [embed] });
      return;
    }

    if (cmd === 'scripts' || cmd === 'list') {
      if (!user) return msg.reply('Use /setup first');

      const scripts = db.prepare('SELECT * FROM scripts WHERE user_id = ? ORDER BY created_at DESC').all(user.id);
      if (!scripts.length) return msg.reply('📂 No scripts found.');

      const embed = new EmbedBuilder()
        .setColor(BRAND_COLOR)
        .setTitle(`📜 Your Scripts (${scripts.length})`)
        .setDescription(scripts.slice(0, 10).map((s, i) =>
          `${i + 1}. **${s.name}** \`${s.id}\` - ${s.status === 'active' ? '🟢 Active' : '🔴 Disabled'}`
        ).join('\n'))
        .setTimestamp();

      await msg.reply({ embeds: [embed] });
      return;
    }

    if (cmd === 'key' || cmd === 'genkey') {
      if (!user) return msg.reply('Use /setup first');

      const scriptId = args[0];
      const hours = parseInt(args[1]) || 0;

      if (!scriptId) return msg.reply(`Usage: ${PREFIX}key <script_id> [hours]`);

      const script = db.prepare('SELECT * FROM scripts WHERE id = ? AND user_id = ?').get(scriptId, user.id);
      if (!script) return msg.reply('❌ Script not found');

      const key = generateKey();
      const expiresAt = hours > 0 ? addHours(hours) : null;
      const id = makeId('key');

      db.prepare(
        `INSERT INTO keys (id, script_id, user_id, key, expires_at, max_uses)
         VALUES (?, ?, ?, ?, ?, 1)`
      ).run(id, scriptId, user.id, key, expiresAt);

      const embed = new EmbedBuilder()
        .setColor(BRAND_COLOR)
        .setTitle('🔑 Key Generated')
        .setDescription(`**Script:** ${script.name}`)
        .addFields(
          { name: 'Key', value: `\`${key}\``, inline: false },
          { name: 'Expires', value: expiresAt ? formatExpiry(expiresAt) : 'Permanent', inline: true }
        )
        .setTimestamp();

      await msg.reply({ embeds: [embed] });
      return;
    }

    if (cmd === 'reset-hwid') {
      if (!user) return msg.reply('Use /setup first');

      const key = args[0];
      if (!key) return msg.reply(`Usage: ${PREFIX}reset-hwid <key>`);

      const keyRecord = db.prepare('SELECT * FROM keys WHERE key = ? AND user_id = ?').get(key, user.id);
      if (!keyRecord) return msg.reply('❌ Key not found');

      if (keyRecord.resettable_at) {
        const lastReset = new Date(keyRecord.resettable_at).getTime();
        const elapsed = Date.now() - lastReset;
        if (elapsed < COOLDOWN_HWID_RESET) {
          const remaining = COOLDOWN_HWID_RESET - elapsed;
          const hours = Math.floor(remaining / 3600000);
          const minutes = Math.floor((remaining % 3600000) / 60000);
          return msg.reply(`⏳ Cooldown: ${hours}h ${minutes}m remaining`);
        }
      }

      db.prepare('UPDATE keys SET hwid = NULL, resettable_at = CURRENT_TIMESTAMP WHERE key = ?').run(key);
      await msg.reply(`✅ HWID reset for \`${key}\``);
      return;
    }

    if (cmd === 'ban' && isOwner(user)) {
      const hwid = args[0];
      if (!hwid) return msg.reply(`Usage: ${PREFIX}ban <hwid>`);
      db.prepare('INSERT OR REPLACE INTO banned_hwids (hwid, banned_by) VALUES (?, ?)').run(hwid, msg.author.id);
      await msg.reply(`✅ HWID \`${hwid}\` banned`);
      return;
    }

    if (cmd === 'unban' && isOwner(user)) {
      const hwid = args[0];
      if (!hwid) return msg.reply(`Usage: ${PREFIX}unban <hwid>`);
      db.prepare('DELETE FROM banned_hwids WHERE hwid = ?').run(hwid);
      await msg.reply(`✅ HWID \`${hwid}\` unbanned`);
      return;
    }
  } catch (error) {
    console.error('Command error:', error);
    await msg.reply('❌ Something went wrong');
  }
});

// ============ START SERVER ============

const port = Number(process.env.PORT || 3000);

(async () => {
  try {
    if (CLIENT_ID && GUILD_ID) {
      const { REST } = require('@discordjs/rest');
      const { Routes } = require('discord-api-types/v10');
      const rest = new REST({ version: '10' }).setToken(DISCORD_TOKEN);
      await rest.put(Routes.applicationGuildCommands(CLIENT_ID, GUILD_ID), { body: [] });
      console.log('Cleared guild commands.');
    }
  } catch (e) {
    console.error('Command deploy failed:', e);
  }

  app.listen(port, '0.0.0.0', () => {
    console.log(`🚀 KarmaForges v7.0 running on port ${port}`);
    console.log(`🌐 Website: ${publicBaseUrl()}`);
  });

  await client.login(DISCORD_TOKEN);
})();

// ====================================================================
// ============ EMBEDDED INDEX.HTML ============
// ====================================================================

const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>KarmaForges | Secure Dashboard</title>
    <meta property="og:site_name" content="KarmaForges" />
    <meta property="og:title" content="KarmaForges - Custom Obfuscator" />
    <meta property="og:description" content="Protect your code against reverse engineering" />
    <meta name="theme-color" content="#6366f1" />
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;800&family=JetBrains+Mono:wght@400;700&family=Fira+Code:wght@400;500&display=swap');
        *, *::before, *::after { box-sizing: border-box; }
        :root { --bg-color: #09090b; --card-bg: rgba(18,18,20,0.65); --primary: #6366f1; --primary-hover: #4f46e5; --discord: #5865F2; --discord-hover: #4752C4; --danger: #ef4444; --success: #10b981; --text-main: #f8fafc; --text-muted: #9ca3af; --border: rgba(255,255,255,0.08); --glow: rgba(99,102,241,0.15); }
        body { font-family: 'Inter', system-ui, sans-serif; background-color: var(--bg-color); color: var(--text-main); margin: 0; padding: 0; min-height: 100vh; -webkit-font-smoothing: antialiased; }
        #auth-wrapper { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: var(--bg-color); display: flex; flex-direction: column; justify-content: center; align-items: center; z-index: 9999; overflow-y: auto; padding: 20px 0; }
        .code-background { position: fixed; top: 0; left: 0; width: 100%; height: 100%; display: flex; justify-content: center; align-items: flex-start; z-index: 1; pointer-events: none; overflow: hidden; opacity: 0.45; }
        .code-column { font-family: 'Fira Code', monospace; font-size: 14px; line-height: 1.8; white-space: pre; text-align: left; animation: scrollCode 60s linear infinite; }
        .kw { color: #ff7b72; font-weight: 500; } .fn { color: #d2a8ff; } .st { color: #a5d6ff; } .cm { color: #8b949e; font-style: italic; } .op { color: #79c0ff; } .vr { color: #c9d1d9; }
        @keyframes scrollCode { 0% { transform: translateY(0); } 100% { transform: translateY(-50%); } }
        .vignette { position: fixed; inset: 0; background: radial-gradient(ellipse at center, transparent 0%, rgba(9,9,11,0.85) 75%, #09090b 100%); z-index: 2; pointer-events: none; }
        .glass-card { background: var(--card-bg); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); border: 1px solid var(--border); box-shadow: 0 0 40px rgba(0,0,0,0.8), inset 0 0 0 1px rgba(255,255,255,0.05); z-index: 10; }
        .fade-in { animation: fadeIn 0.4s ease-out forwards; }
        .hidden { display: none !important; }
        #dashboard-content { display: none; width: 100%; height: 100vh; flex-direction: row; position: relative; }
        .sidebar { width: 280px; background: var(--card-bg); backdrop-filter: blur(16px); border-right: 1px solid var(--border); padding: 30px 20px; display: flex; flex-direction: column; flex-shrink: 0; height: 100vh; overflow-y: auto; }
        .sidebar::-webkit-scrollbar { width: 4px; } .sidebar::-webkit-scrollbar-thumb { background-color: var(--border); border-radius: 6px; }
        .brand { font-size: 20px; font-weight: 800; color: white; display: flex; align-items: center; gap: 8px; margin-bottom: 35px; letter-spacing: -0.5px; padding-left: 5px; }
        .brand span { color: var(--primary); } .brand-icon { width: 22px; height: 22px; color: var(--primary); }
        .nav-item { color: var(--text-muted); padding: 12px 16px; border-radius: 10px; cursor: pointer; font-weight: 600; transition: all 0.2s ease; display: flex; align-items: center; gap: 10px; font-size: 14px; }
        .nav-item:hover { background-color: rgba(255,255,255,0.03); color: white; }
        .nav-item.active { background-color: var(--glow); color: var(--primary); }
        .nav-item .icon { width: 20px; height: 20px; flex-shrink: 0; }
        .main-content-wrapper { flex: 1; display: flex; flex-direction: column; height: 100vh; overflow: hidden; background-color: var(--bg-color); }
        .top-navbar { display: flex; justify-content: flex-end; align-items: center; padding: 15px 30px; background: var(--card-bg); backdrop-filter: blur(16px); border-bottom: 1px solid var(--border); gap: 20px; z-index: 90; }
        .user-profile-top { display: flex; align-items: center; gap: 12px; }
        .user-info-top { display: flex; flex-direction: column; align-items: flex-end; }
        .user-name { font-weight: 600; font-size: 13px; color: white; }
        .user-id { color: var(--text-muted); font-size: 11px; font-family: 'JetBrains Mono', monospace; }
        .logout-link { color: var(--danger); cursor: pointer; font-weight: 600; font-size: 12px; }
        .logout-link:hover { color: #dc2626; }
        .user-avatar { width: 38px; height: 38px; border-radius: 50%; object-fit: cover; border: 2px solid var(--border); }
        .content-scroll { flex: 1; overflow-y: auto; padding: 30px; }
        .content-scroll::-webkit-scrollbar { width: 6px; } .content-scroll::-webkit-scrollbar-thumb { background-color: #3f3f46; border-radius: 8px; }
        .content-container { max-width: 1100px; margin: 0 auto; }
        h2 { font-size: 20px; margin-top: 0; margin-bottom: 20px; font-weight: 800; letter-spacing: -0.5px; }
        .panel { background: var(--card-bg); backdrop-filter: blur(16px); border: 1px solid var(--border); border-radius: 14px; padding: 25px; margin-bottom: 25px; box-shadow: 0 10px 30px -10px rgba(0,0,0,0.5); }
        input[type="text"], input[type="number"], input[type="email"], input[type="password"] { width: 100%; background-color: rgba(0,0,0,0.3); border: 1px solid var(--border); color: var(--text-main); padding: 14px 16px; border-radius: 10px; margin-bottom: 15px; font-family: 'Inter', sans-serif; font-size: 13.5px; font-weight: 500; transition: all 0.2s ease; }
        select { width: 100%; background-color: rgba(0,0,0,0.3); border: 1px solid var(--border); color: var(--text-main); border-radius: 10px; margin-bottom: 25px; font-family: 'Inter', sans-serif; font-weight: 500; font-size: 14px !important; padding: 14px 16px; -webkit-appearance: none; -moz-appearance: none; appearance: none; background-image: url("data:image/svg+xml;charset=US-ASCII,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%22292.4%22%20height%3D%22292.4%22%3E%3Cpath%20fill%3D%22%23ffffff%22%20d%3D%22M287%2069.4a17.6%2017.6%200%200%200-13-5.4H18.4c-5%200-9.3%201.8-12.9%205.4A17.6%2017.6%200%200%200%200%2082.2c0%205%201.8%209.3%205.4%2012.9l128%20127.9c3.6%203.6%207.8%205.4%2012.8%205.4s9.2-1.8%2012.8-5.4L287%2095c3.5-3.5%205.4-7.8%205.4-12.8%200-5-1.9-9.2-5.5-12.8z%22%2F%3E%3C%2Fsvg%3E"); background-repeat: no-repeat; background-position: right 16px top 50%; background-size: 12px auto; }
        select option { font-size: 14px !important; background-color: var(--bg-color); color: var(--text-main); }
        textarea { width: 100%; background-color: rgba(0,0,0,0.3); border: 1px solid var(--border); color: var(--text-main); border-radius: 10px; margin-bottom: 15px; font-family: 'JetBrains Mono', monospace !important; font-size: 13px; padding: 18px 20px !important; line-height: 1.6; resize: vertical; min-height: 150px; }
        input:focus, select:focus, textarea:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px var(--glow); }
        .checkbox-container { display: flex; align-items: center; gap: 8px; font-size: 13px; font-weight: 600; color: var(--text-main); cursor: pointer; padding: 10px 14px; background: rgba(0,0,0,0.2); border: 1px solid var(--border); border-radius: 10px; transition: all 0.2s; width: fit-content; }
        .checkbox-container:hover { background: rgba(0,0,0,0.4); border-color: var(--primary); }
        .checkbox-container input { width: 16px; height: 16px; cursor: pointer; accent-color: var(--primary); }
        button { border: none; padding: 11px 18px; border-radius: 10px; font-weight: 600; cursor: pointer; transition: all 0.2s ease; font-size: 13px; display: inline-flex; align-items: center; justify-content: center; gap: 8px; }
        .btn-primary { background-color: var(--primary); color: white; box-shadow: 0 4px 12px rgba(99,102,241,0.3); }
        .btn-primary:hover { background-color: var(--primary-hover); transform: translateY(-1px); }
        .btn-danger { background-color: rgba(239,68,68,0.1); color: var(--danger); border: 1px solid rgba(239,68,68,0.2); }
        .btn-danger:hover { background-color: rgba(239,68,68,0.2); }
        .btn-success { background-color: rgba(16,185,129,0.1); color: var(--success); border: 1px solid rgba(16,185,129,0.2); }
        .btn-success:hover { background-color: rgba(16,185,129,0.2); }
        .btn-outline { background-color: rgba(0,0,0,0.2); border: 1px solid var(--border); color: var(--text-main); }
        .btn-outline:hover { border-color: var(--primary); color: var(--primary); background-color: rgba(99,102,241,0.1); }
        .scripts-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 20px; }
        .script-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 16px; transition: all 0.3s; }
        .script-card:hover { border-color: var(--primary); transform: translateY(-3px); box-shadow: 0 8px 30px rgba(0,0,0,0.3); }
        .card-title { font-weight: 600; font-size: 15px; margin-bottom: 8px; }
        .card-meta { font-size: 12px; color: var(--text-muted); margin-bottom: 12px; }
        .card-actions { display: flex; gap: 8px; flex-wrap: wrap; }
        .card-actions .btn { flex: 1; padding: 8px 12px; font-size: 12px; }
        .badge { display: inline-block; padding: 2px 10px; border-radius: 6px; font-size: 11px; font-weight: 600; }
        .badge-success { background: rgba(16,185,129,0.15); color: var(--success); border: 1px solid rgba(16,185,129,0.15); }
        .badge-danger { background: rgba(239,68,68,0.15); color: var(--danger); border: 1px solid rgba(239,68,68,0.15); }
        .badge-warning { background: rgba(245,158,11,0.15); color: #f59e0b; border: 1px solid rgba(245,158,11,0.15); }
        .badge-primary { background: rgba(99,102,241,0.2); color: var(--primary); border: 1px solid rgba(99,102,241,0.15); }
        .view-section { display: none; }
        .view-section.active { display: block; animation: fadeIn 0.3s ease; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        .flex { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
        .flex-between { display: flex; justify-content: space-between; align-items: center; }
        .mt-16 { margin-top: 16px; }
        .text-muted { color: var(--text-muted); }
        .w-full { width: 100%; }
        .stat { background:rgba(0,0,0,0.3); border:1px solid var(--border); border-radius:12px; padding:16px; text-align:center; }
        .stat .num { font-size:28px; font-weight:900; color:var(--primary); }
        .stat .label { font-size:13px; color:var(--text-muted); }
        .stats-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:16px; margin-top:16px; }
        @media (max-width: 768px) {
            .sidebar { display: none; position: fixed; top: 0; left: 0; width: 260px; height: 100vh; z-index: 100; }
            .sidebar.open { display: block; }
            .top-navbar { padding: 15px; flex-direction: column; align-items: stretch; }
            .content-scroll { padding: 20px 15px; }
            .mobile-menu-btn { background: none; border: none; color: white; padding: 5px; cursor: pointer; display: block !important; }
            .mobile-brand { display: flex; justify-content: space-between; align-items: center; width: 100%; }
            .scripts-grid { grid-template-columns: 1fr; }
            .sidebar-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 99; }
            .sidebar-overlay.open { display: block; }
        }
        .mobile-menu-btn { display: none; }
    </style>
</head>
<body>
<div id="auth-wrapper">
    <div class="code-background" aria-hidden="true">
        <div class="code-column">
            <div class="code-block">
<span class="cm">-- [KarmaForges] Advanced Protection</span>
<span class="kw">local</span> <span class="vr">Core</span> <span class="op">=</span> <span class="vr">game</span><span class="op">:</span><span class="fn">GetService</span>(<span class="st">"CoreGui"</span>)
<span class="kw">local</span> <span class="vr">KeySystem</span> <span class="op">=</span> <span class="fn">require</span>(<span class="st">"modules/LicenseManager"</span>)
<span class="kw">function</span> <span class="vr">ProtectScript</span>(<span class="vr">source</span>)
    <span class="kw">local</span> <span class="vr">ast</span> <span class="op">=</span> <span class="fn">parse</span>(<span class="vr">source</span>)
    <span class="vr">ast</span> <span class="op">=</span> <span class="vr">VirtualMachine</span><span class="op">:</span><span class="fn">Wrap</span>(<span class="vr">ast</span>)
    <span class="kw">return</span> <span class="vr">Compiler</span><span class="op">:</span><span class="fn">Build</span>(<span class="vr">ast</span>)
<span class="kw">end</span>
<span class="kw">function</span> <span class="vr">ValidateUserKey</span>(<span class="vr">key</span>, <span class="vr">hwid</span>)
    <span class="kw">if not</span> <span class="vr">KeySystem</span><span class="op">.</span><span class="fn">CheckWhitelist</span>(<span class="vr">hwid</span>) <span class="kw">then</span>
        <span class="vr">KeySystem</span><span class="op">.</span><span class="fn">IssueBan</span>(<span class="vr">hwid</span>, <span class="st">"Unauthorized Access"</span>)
        <span class="kw">return</span> <span class="kw">false</span>
    <span class="kw">end</span>
    <span class="kw">return</span> <span class="kw">true</span>
<span class="kw">end</span>
<br><br></div>
            <div class="code-block">
<span class="cm">-- [KarmaForges] Advanced Protection</span>
<span class="kw">local</span> <span class="vr">Core</span> <span class="op">=</span> <span class="vr">game</span><span class="op">:</span><span class="fn">GetService</span>(<span class="st">"CoreGui"</span>)
<span class="kw">local</span> <span class="vr">KeySystem</span> <span class="op">=</span> <span class="fn">require</span>(<span class="st">"modules/LicenseManager"</span>)
<span class="kw">function</span> <span class="vr">ProtectScript</span>(<span class="vr">source</span>)
    <span class="kw">local</span> <span class="vr">ast</span> <span class="op">=</span> <span class="fn">parse</span>(<span class="vr">source</span>)
    <span class="vr">ast</span> <span class="op">=</span> <span class="vr">VirtualMachine</span><span class="op">:</span><span class="fn">Wrap</span>(<span class="vr">ast</span>)
    <span class="kw">return</span> <span class="vr">Compiler</span><span class="op">:</span><span class="fn">Build</span>(<span class="vr">ast</span>)
<span class="kw">end</span>
<span class="kw">function</span> <span class="vr">ValidateUserKey</span>(<span class="vr">key</span>, <span class="vr">hwid</span>)
    <span class="kw">if not</span> <span class="vr">KeySystem</span><span class="op">.</span><span class="fn">CheckWhitelist</span>(<span class="vr">hwid</span>) <span class="kw">then</span>
        <span class="vr">KeySystem</span><span class="op">.</span><span class="fn">IssueBan</span>(<span class="vr">hwid</span>, <span class="st">"Unauthorized Access"</span>)
        <span class="kw">return</span> <span class="kw">false</span>
    <span class="kw">end</span>
    <span class="kw">return</span> <span class="kw">true</span>
<span class="kw">end</span>
<br><br></div>
        </div>
    </div>
    <div class="vignette"></div>
    <div id="auth-login" class="glass-card rounded-2xl p-6 sm:p-10 max-w-[420px] w-[90%] mx-auto relative z-10 fade-in text-center flex flex-col justify-center my-auto">
        <div class="flex justify-center mb-5">
            <div class="bg-gray-800/80 p-3.5 rounded-2xl border border-gray-600/30 shadow-[0_0_20px_rgba(88,101,242,0.15)]">
                <svg class="w-8 h-8 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M8 7v4m8-4v4"></path></svg>
            </div>
        </div>
        <h1 class="text-xl sm:text-2xl font-bold text-white tracking-wide mb-1.5">Karma<span style="color:var(--primary)">Forges</span></h1>
        <p class="text-[13px] text-gray-400 mb-7">Ultimate script protection & key system</p>
        <div class="space-y-4">
            <a href="/api/auth/discord" class="w-full bg-[#5865F2] hover:bg-[#4752C4] transition-all duration-300 text-white font-medium py-3 px-4 rounded-xl flex items-center justify-center shadow-[0_0_15px_rgba(88,101,242,0.3)] hover:shadow-[0_0_25px_rgba(88,101,242,0.5)] transform hover:-translate-y-0.5 text-sm">
                <svg class="w-5 h-5 mr-3 fill-current" viewBox="0 0 127.14 96.36"><path d="M107.7,8.07A105.15,105.15,0,0,0,81.47,0a72.06,72.06,0,0,0-3.36,6.83A97.68,97.68,0,0,0,49,6.83,72.37,72.37,0,0,0,45.64,0,105.89,105.89,0,0,0,19.39,8.09C2.79,32.65-1.71,56.6.54,80.21h0A105.73,105.73,0,0,0,32.71,96.36,77.7,77.7,0,0,0,39.6,85.25a68.42,68.42,0,0,1-10.85-5.18c.91-.66,1.8-1.34,2.66-2a75.57,75.57,0,0,0,64.32,0c.87.71,1.76,1.39,2.66,2a68.68,68.68,0,0,1-10.87,5.19,77,77,0,0,0,6.89,11.1A105.25,105.25,0,0,0,126.6,80.22h0C129.24,52.84,122.09,29.11,107.7,8.07ZM42.45,65.69C36.18,65.69,31,60,31,53s5-12.74,11.43-12.74S54,46,53.89,53,48.84,65.69,42.45,65.69Zm42.24,0C78.41,65.69,73.31,60,73.31,53s5-12.74,11.43-12.74S96.1,46,96,53,91.08,65.69,84.69,65.69Z"/></svg>
                Login with Discord
            </a>
        </div>
    </div>
</div>
<div id="dashboard-content">
    <div class="sidebar-overlay" onclick="closeSidebar()"></div>
    <div class="sidebar" id="sidebar">
        <div class="brand"><svg class="brand-icon flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>Karma<span>Forges</span></div>
        <div class="nav-items" style="display:flex;flex-direction:column;gap:4px;flex:1;">
            <div class="nav-item active" onclick="switchView('overview', this)"><svg class="icon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"></path></svg>Overview</div>
            <div class="nav-item" onclick="switchView('scripts', this)"><svg class="icon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path></svg>Scripts</div>
            <div class="nav-item" onclick="switchView('panels', this)"><svg class="icon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>Panels</div>
            <div class="nav-item" onclick="switchView('keys', this)"><svg class="icon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"></path></svg>Keys</div>
            <div class="nav-item" onclick="switchView('hwids', this)"><svg class="icon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"></path></svg>HWID Bans</div>
            <div class="nav-item" onclick="switchView('settings', this)"><svg class="icon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>Settings</div>
        </div>
    </div>
    <div class="main-content-wrapper">
        <div class="top-navbar">
            <div class="mobile-brand" style="display:flex;justify-content:space-between;align-items:center;width:100%;">
                <div class="brand" style="margin-bottom:0;font-size:18px;">Karma<span>Forges</span></div>
                <button class="mobile-menu-btn" onclick="toggleSidebar()" style="display:none;"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"></path></svg></button>
            </div>
            <div class="user-profile-top">
                <div class="user-info-top"><span class="user-name" id="displayUsername">Loading...</span><span class="user-id" id="displayUserId">ID: ---</span><span class="logout-link" onclick="logout()">Log out</span></div>
                <img id="userAvatar" class="user-avatar" src="" alt="Avatar">
            </div>
        </div>
        <div class="content-scroll">
            <div class="content-container">
                <div id="view-overview" class="view-section active">
                    <div class="panel">
                        <h2>Welcome, <span id="welcomeName" style="color:var(--primary);">User</span></h2>
                        <p class="text-muted">Manage your scripts, panels, and keys from one place.</p>
                        <div class="stats-grid" id="statsGrid">
                            <div class="stat"><div class="num" id="statScripts">0</div><div class="label">Scripts</div></div>
                            <div class="stat"><div class="num" id="statPanels">0</div><div class="label">Panels</div></div>
                            <div class="stat"><div class="num" id="statKeys">0</div><div class="label">Keys</div></div>
                            <div class="stat"><div class="num" id="statBanned">0</div><div class="label">Banned HWIDs</div></div>
                        </div>
                    </div>
                </div>
                <div id="view-scripts" class="view-section">
                    <div class="panel">
                        <h2>Your Scripts</h2>
                        <div class="flex" style="margin-bottom:16px;">
                            <input type="text" id="scriptName" placeholder="Script name" style="flex:1;min-width:200px;margin:0;">
                            <label class="checkbox-container"><input type="checkbox" id="ffaModeCheck"> FFA Mode</label>
                            <label class="checkbox-container"><input type="checkbox" id="compressModeCheck"> Compress</label>
                            <button class="btn btn-primary" onclick="createScript()">Create</button>
                        </div>
                        <textarea id="scriptCode" rows="8" placeholder="Paste your Lua code here..."></textarea>
                    </div>
                    <div id="scriptsList" class="scripts-grid"></div>
                </div>
                <div id="view-panels" class="view-section">
                    <div class="panel">
                        <h2>Discord Panels</h2>
                        <div class="grid-2" style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
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
                <div id="view-keys" class="view-section">
                    <div class="panel">
                        <h2>Generate Keys</h2>
                        <select id="keyPanel"><option value="">Select panel...</option></select>
                        <input type="number" id="keyDuration" placeholder="Duration (hours, 0 = permanent)" value="0">
                        <input type="text" id="keyNote" placeholder="Note (optional)">
                        <div class="flex" style="margin-top:10px;">
                            <button class="btn btn-primary" onclick="generateKey()">Generate Key</button>
                            <button class="btn btn-outline" onclick="addTimeAll()">Add Time to All</button>
                        </div>
                    </div>
                    <div id="keysList" class="scripts-grid"></div>
                </div>
                <div id="view-hwids" class="view-section">
                    <div class="panel">
                        <h2>Ban HWID</h2>
                        <div class="flex">
                            <input type="text" id="banHwidInput" placeholder="Enter HWID to ban" style="flex:1;margin:0;">
                            <button class="btn btn-danger" onclick="banHwid()">Ban</button>
                        </div>
                    </div>
                    <div id="hwidsList" class="scripts-grid"></div>
                </div>
                <div id="view-settings" class="view-section">
                    <div class="panel">
                        <h2>Account Settings</h2>
                        <div style="display:flex;flex-direction:column;gap:12px;">
                            <div><h4 style="margin-bottom:4px;">Referral Code</h4><p class="text-muted" id="referralCodeDisplay">Loading...</p></div>
                            <div style="border-top:1px solid var(--border);padding-top:12px;"><h4 style="margin-bottom:4px;color:var(--danger);">Danger Zone</h4><button class="btn btn-danger" onclick="deleteAccount()">Delete Account</button></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
<script>
    let currentData = { scripts: [], panels: [], keys: [], bannedHWIDs: [] };
    let serverTime = Date.now();
    function getHeaders() { return { 'Content-Type': 'application/json' }; }
    function checkLogin() {
        const urlParams = new URLSearchParams(window.location.hash.replace('#', '?'));
        let user = urlParams.get('user');
        let id = urlParams.get('id');
        let avatar = urlParams.get('avatar');
        if (user && id) {
            localStorage.setItem('kf_user', user);
            localStorage.setItem('kf_id', id);
            localStorage.setItem('kf_avatar', avatar || '');
            window.history.replaceState({}, document.title, window.location.pathname);
        } else {
            user = localStorage.getItem('kf_user');
            id = localStorage.getItem('kf_id');
            avatar = localStorage.getItem('kf_avatar');
        }
        if (user && id) {
            document.getElementById('auth-wrapper').style.display = 'none';
            document.getElementById('dashboard-content').style.display = 'flex';
            document.getElementById('displayUsername').innerText = user;
            document.getElementById('displayUserId').innerText = 'ID: ' + id;
            document.getElementById('welcomeName').innerText = user;
            document.getElementById('userAvatar').src = (avatar && avatar !== 'null') ? 'https://cdn.discordapp.com/avatars/' + id + '/' + avatar + '.png' : 'https://cdn.discordapp.com/embed/avatars/0.png';
            document.querySelector('.mobile-menu-btn').style.display = 'block';
            loadData();
        } else {
            document.getElementById('auth-wrapper').style.display = 'flex';
            document.getElementById('dashboard-content').style.display = 'none';
        }
    }
    function logout() { localStorage.clear(); window.location.href = '/'; }
    function toggleSidebar() { document.getElementById('sidebar').classList.toggle('open'); document.querySelector('.sidebar-overlay').classList.toggle('open'); }
    function closeSidebar() { document.getElementById('sidebar').classList.remove('open'); document.querySelector('.sidebar-overlay').classList.remove('open'); }
    function switchView(view, el) {
        document.querySelectorAll('.view-section').forEach(v => v.classList.remove('active'));
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        document.getElementById('view-' + view).classList.add('active');
        if (el) el.classList.add('active');
        closeSidebar();
    }
    async function loadData() {
        try {
            const res = await fetch('/api/data', { headers: getHeaders() });
            const data = await res.json();
            if (data.error) return;
            currentData = data;
            serverTime = data.serverTime || Date.now();
            renderAll();
        } catch(e) { console.error(e); }
    }
    function renderAll() {
        renderStats(); renderScripts(); renderPanels(); renderKeys(); renderHwids(); updateSelects();
    }
    function renderStats() {
        document.getElementById('statScripts').textContent = currentData.scripts.length;
        document.getElementById('statPanels').textContent = currentData.panels.length;
        document.getElementById('statKeys').textContent = currentData.keys.length;
        document.getElementById('statBanned').textContent = currentData.bannedHWIDs.length;
    }
    function escapeHtml(text) { const div = document.createElement('div'); div.textContent = text; return div.innerHTML; }
    function renderScripts() {
        const container = document.getElementById('scriptsList');
        if (!currentData.scripts.length) { container.innerHTML = '<div style="grid-column:1/-1;padding:30px;text-align:center;color:var(--text-muted);background:rgba(0,0,0,0.2);border-radius:12px;border:1px dashed var(--border);">No scripts yet. Create one above.</div>'; return; }
        let html = '';
        for (const s of currentData.scripts) {
            const statusBadge = s.status === 'active' ? 'badge-success' : 'badge-danger';
            const statusText = s.status === 'active' ? 'Active' : 'Disabled';
            const ffaBadge = s.ffa_mode ? '<span class="badge badge-warning">FFA</span>' : '';
            const compressBadge = s.compress_mode ? '<span class="badge badge-primary">Compressed</span>' : '';
            const date = new Date(s.created_at).toLocaleDateString();
            html += '<div class="script-card"><div class="card-title">' + escapeHtml(s.name) + '</div><div class="card-meta"><span class="badge ' + statusBadge + '">' + statusText + '</span> ' + ffaBadge + ' ' + compressBadge + ' <span style="margin-left:8px;">' + date + '</span></div><div class="card-actions"><button class="btn btn-outline" onclick="toggleScript(\'' + s.id + '\')">' + (s.status === 'active' ? 'Disable' : 'Enable') + '</button><button class="btn btn-outline" onclick="toggleFfa(\'' + s.id + '\')">' + (s.ffa_mode ? 'Disable FFA' : 'Enable FFA') + '</button><button class="btn btn-danger" onclick="deleteScript(\'' + s.id + '\')">Delete</button></div></div>';
        }
        container.innerHTML = html;
    }
    function renderPanels() {
        const container = document.getElementById('panelsList');
        if (!currentData.panels.length) { container.innerHTML = '<div style="grid-column:1/-1;padding:30px;text-align:center;color:var(--text-muted);background:rgba(0,0,0,0.2);border-radius:12px;border:1px dashed var(--border);">No panels yet. Create one above.</div>'; return; }
        let html = '';
        for (const p of currentData.panels) {
            html += '<div class="script-card"><div class="card-title">' + escapeHtml(p.name) + '</div><div class="card-meta">' + escapeHtml(p.description || 'No description') + '</div><div class="card-actions"><button class="btn btn-success" onclick="sendPanel(\'' + p.id + '\')">Send to Discord</button><button class="btn btn-danger" onclick="deletePanel(\'' + p.id + '\')">Delete</button></div></div>';
        }
        container.innerHTML = html;
    }
    function renderKeys() {
        const container = document.getElementById('keysList');
        if (!currentData.keys.length) { container.innerHTML = '<div style="grid-column:1/-1;padding:30px;text-align:center;color:var(--text-muted);background:rgba(0,0,0,0.2);border-radius:12px;border:1px dashed var(--border);">No keys generated yet.</div>'; return; }
        let html = '';
        for (const k of currentData.keys) {
            const expired = k.expires_at && new Date(k.expires_at).getTime() < serverTime;
            let status = 'Active', badgeClass = 'badge-success';
            if (expired) { status = 'Expired'; badgeClass = 'badge-danger'; }
            else if (k.hwid) { status = 'HWID Locked'; badgeClass = 'badge-warning'; }
            html += '<div class="script-card"><div class="card-title" style="font-family:monospace;font-size:13px;color:var(--primary);">' + escapeHtml(k.key) + '</div><div class="card-meta"><span class="badge ' + badgeClass + '">' + status + '</span> ' + (k.note ? '<span style="margin-left:8px;">' + escapeHtml(k.note) + '</span>' : '') + '</div><div class="card-actions"><button class="btn btn-danger" onclick="deleteKey(\'' + k.key + '\')">Delete</button></div></div>';
        }
        container.innerHTML = html;
    }
    function renderHwids() {
        const container = document.getElementById('hwidsList');
        if (!currentData.bannedHWIDs.length) { container.innerHTML = '<div style="grid-column:1/-1;padding:30px;text-align:center;color:var(--text-muted);background:rgba(0,0,0,0.2);border-radius:12px;border:1px dashed var(--border);">No banned HWIDs.</div>'; return; }
        let html = '';
        for (const h of currentData.bannedHWIDs) {
            html += '<div class="script-card"><div class="card-title" style="font-family:monospace;font-size:13px;color:var(--danger);">' + escapeHtml(h.hwid) + '</div><div class="card-meta">Banned ' + new Date(h.created_at).toLocaleDateString() + '</div><div class="card-actions"><button class="btn btn-outline" onclick="unbanHwid(\'' + h.hwid + '\')">Unban</button></div></div>';
        }
        container.innerHTML = html;
    }
    function updateSelects() {
        const panelScript = document.getElementById('panelScript');
        panelScript.innerHTML = '<option value="">Select script...</option>';
        for (const s of currentData.scripts) { panelScript.innerHTML += '<option value="' + s.id + '">' + escapeHtml(s.name) + '</option>'; }
        const keyPanel = document.getElementById('keyPanel');
        keyPanel.innerHTML = '<option value="">Select panel...</option>';
        for (const p of currentData.panels) { keyPanel.innerHTML += '<option value="' + p.id + '">' + escapeHtml(p.name) + '</option>'; }
    }
    async function createScript() {
        const name = document.getElementById('scriptName').value.trim();
        const code = document.getElementById('scriptCode').value;
        const compressMode = document.getElementById('compressModeCheck').checked;
        if (!name || !code) return alert('Please enter a name and code.');
        await fetch('/api/create-script', { method:'POST', headers:getHeaders(), body:JSON.stringify({name,code,compressMode}) });
        document.getElementById('scriptName').value = '';
        document.getElementById('scriptCode').value = '';
        document.getElementById('ffaModeCheck').checked = false;
        document.getElementById('compressModeCheck').checked = false;
        loadData();
    }
    async function toggleScript(id) { await fetch('/api/scripts/'+id+'/toggle', { method:'PUT', headers:getHeaders() }); loadData(); }
    async function toggleFfa(id) { await fetch('/api/scripts/'+id+'/ffa', { method:'PUT', headers:getHeaders() }); loadData(); }
    async function deleteScript(id) { if (!confirm('Delete this script?')) return; await fetch('/api/delete-script', { method:'POST', headers:getHeaders(), body:JSON.stringify({id}) }); loadData(); }
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
    async function sendPanel(id) { await fetch('/api/send-panel', { method:'POST', headers:getHeaders(), body:JSON.stringify({panelId:id}) }); alert('Panel sent to Discord!'); }
    async function deletePanel(id) { if (!confirm('Delete this panel?')) return; await fetch('/api/delete-panel', { method:'POST', headers:getHeaders(), body:JSON.stringify({id}) }); loadData(); }
    async function generateKey() {
        const panelId = document.getElementById('keyPanel').value;
        const durationHours = parseInt(document.getElementById('keyDuration').value) || 0;
        const note = document.getElementById('keyNote').value.trim();
        if (!panelId) return alert('Please select a panel.');
        await fetch('/api/generate-key', { method:'POST', headers:getHeaders(), body:JSON.stringify({panelId,durationHours,note}) });
        document.getElementById('keyNote').value = '';
        loadData();
    }
    async function deleteKey(key) { if (!confirm('Delete this key?')) return; await fetch('/api/delete-key', { method:'POST', headers:getHeaders(), body:JSON.stringify({key}) }); loadData(); }
    async function addTimeAll() { const hours = prompt('How many hours to add to all keys?'); if (!hours || isNaN(hours)) return; await fetch('/api/add-time-all', { method:'POST', headers:getHeaders(), body:JSON.stringify({hours:parseInt(hours)}) }); loadData(); }
    async function banHwid() { const hwid = document.getElementById('banHwidInput').value.trim(); if (!hwid) return alert('Enter an HWID to ban.'); await fetch('/api/ban-hwid', { method:'POST', headers:getHeaders(), body:JSON.stringify({hwid}) }); document.getElementById('banHwidInput').value = ''; loadData(); }
    async function unbanHwid(hwid) { if (!confirm('Unban this HWID?')) return; await fetch('/api/unban-hwid', { method:'POST', headers:getHeaders(), body:JSON.stringify({hwid}) }); loadData(); }
    async function deleteAccount() { if (!confirm('Are you sure? This action is permanent.')) return; const confirmText = prompt('Type DELETE to confirm:'); if (confirmText !== 'DELETE') return alert('Confirmation failed.'); await fetch('/api/delete-account', { method:'POST', headers:getHeaders(), body:JSON.stringify({confirm:'DELETE'}) }); alert('Account deleted.'); logout(); }
    checkLogin();
</script>
</body>
</html>`;

console.log('✅ KarmaForges v7.0 loaded with embedded index.html');
