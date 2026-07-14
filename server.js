// server.js – KarmaForges v7.0 Complete Edition
// Full integration with your index.html dashboard

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

// ============ ENVIRONMENT ============
require('dotenv').config();

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
const BOT_PERMISSIONS = process.env.BOT_PERMISSIONS || '8';
const COOLDOWN_HWID_RESET = 24 * 60 * 60 * 1000; // 24 hours

if (!DISCORD_TOKEN || !CLIENT_SECRET) {
  console.error('Missing DISCORD_TOKEN or CLIENT_SECRET.');
  process.exit(1);
}

console.log('🐱 KarmaForges v7.0 starting...');
console.log(`Database: ${DATABASE_PATH}`);
console.log(`Base URL: ${PUBLIC_BASE_URL}`);
console.log(`Max scripts per user: ${MAX_SCRIPTS}`);

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

    const logId = makeId('log');
    db.prepare(
      'INSERT INTO obfuscation_logs (id, user_id, script_id, layers) VALUES (?, ?, ?, ?)'
    ).run(logId, userId, '', JSON.stringify(layers));

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
app.use(express.static(path.join(__dirname, 'public')));

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
    let dbUser = db.prepare('SELECT * FROM users WHERE discord_id = ? AND deleted_at IS NULL').get(user.id);
    if (!dbUser) {
      const id = makeId('user');
      const referralCode = generateReferralCode();
      db.prepare(
        `INSERT INTO users (id, discord_id, username, avatar, referral_code)
         VALUES (?, ?, ?, ?, ?)`
      ).run(id, user.id, user.username, user.avatar || '', referralCode);
      dbUser = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(user.id);
    } else {
      db.prepare('UPDATE users SET username = ?, avatar = ?, updated_at = CURRENT_TIMESTAMP WHERE discord_id = ?')
        .run(user.username, user.avatar || '', user.id);
    }

    const avatarUrl = user.avatar ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png` : '';
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

// ============ SCRIPT MANAGEMENT ============

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

app.post('/api/create-script', requireAuth, (req, res) => {
  const user = req.session.user;
  const { name, code, compressMode, type } = req.body;
  if (!name || !code) return res.status(400).json({ error: 'Missing name or code' });

  const count = db.prepare('SELECT COUNT(*) as total FROM scripts WHERE user_id = ?').get(user.id).total;
  if (count >= MAX_SCRIPTS) {
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

  // Send panel to Discord via bot
  if (client.isReady()) {
    const channel = client.channels.cache.get(panel.channel_id);
    if (channel) {
      const embed = new EmbedBuilder()
        .setColor(BRAND_COLOR)
        .setTitle(panel.name)
        .setDescription(panel.description || 'Use the buttons below to manage your script.')
        .addFields(
          { name: 'Script ID', value: panel.script_id, inline: true }
        )
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

// Serve the index.html with user data from session
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

// Dashboard route - serves the same index.html but client-side handles the hash
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
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
          `${PREFIX}credits – Check your credits',
          '',
          '**Scripts**',
          `${PREFIX}upload <name> [file] – Upload a script`,
          `${PREFIX}script <id> – View script details`,
          `${PREFIX}toggle <id> – Enable/disable script`,
          '',
          '**Keys**',
          `${PREFIX}key <script_id> [hours] [max_uses] – Generate key`,
          `${PREFIX}reset-hwid <key> – Reset HWID (24h cooldown)`,
          `${PREFIX}revoke <key> – Revoke a key`,
          '',
          '**Whitelist**',
          `${PREFIX}whitelist <script_id> <@user> [hours] – Whitelist user`,
          `${PREFIX}unwhitelist <@user> – Remove from whitelist`,
          `${PREFIX}wllist – List whitelisted users`,
          '',
          '**Admin**',
          `${PREFIX}ban <hwid> – Ban HWID`,
          `${PREFIX}unban <hwid> – Unban HWID`,
          `${PREFIX}stats – Server statistics`
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

      const sc = db.prepare('SELECT COUNT(*) as count FROM scripts WHERE user_id = ?').get(dbUser.id).count;
      const kc = db.prepare('SELECT COUNT(*) as count FROM keys WHERE user_id = ?').get(dbUser.id).count;

      const embed = new EmbedBuilder()
        .setColor(BRAND_COLOR)
        .setTitle('✅ Account Ready')
        .setDescription(`Welcome ${msg.author.username}!`)
        .addFields(
          { name: 'Scripts', value: String(sc), inline: true },
          { name: 'Keys', value: String(kc), inline: true },
          { name: 'Credits', value: String(dbUser.credits || 0), inline: true }
        )
        .setFooter({ text: 'KarmaForges' })
        .setTimestamp();

      await msg.reply({ embeds: [embed] });
      return;
    }

    // Add more commands as needed...
  } catch (error) {
    console.error('Command error:', error);
    await msg.reply('❌ Something went wrong');
  }
});

// ============ INTERACTION HANDLERS ============

client.on('interactionCreate', async (interaction) => {
  if (!interaction.isButton() && !interaction.isModalSubmit()) return;

  try {
    const user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(interaction.user.id);
    if (!user) {
      return interaction.reply({ content: 'Use /setup first', ephemeral: true });
    }

    const customId = interaction.customId;
    const action = customId[0];
    const scriptId = customId.substring(3);

    const script = db.prepare('SELECT * FROM scripts WHERE id = ? AND user_id = ?').get(scriptId, user.id);
    if (!script) {
      return interaction.reply({ content: '❌ Script not found', ephemeral: true });
    }

    if (interaction.isButton()) {
      if (action === 'v') {
        const keyCount = db.prepare('SELECT COUNT(*) as count FROM keys WHERE script_id = ?').get(scriptId).count;
        const embed = new EmbedBuilder()
          .setColor(BRAND_COLOR)
          .setTitle(script.name)
          .addFields(
            { name: 'Version', value: script.version || '1.0.0', inline: true },
            { name: 'Status', value: script.status === 'active' ? '🟢 Active' : '🔴 Disabled', inline: true },
            { name: 'Keys', value: String(keyCount), inline: true },
            { name: 'FFA Mode', value: script.ffa_mode ? '✅' : '❌', inline: true }
          )
          .setTimestamp();

        await interaction.reply({ embeds: [embed], ephemeral: true });
      } else if (action === 'r') {
        const modal = new ModalBuilder()
          .setCustomId(`rm_${scriptId}`)
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
      } else if (action === 'i') {
        const keys = db.prepare(
          'SELECT * FROM keys WHERE script_id = ? AND user_id = ? ORDER BY created_at DESC'
        ).all(scriptId, user.id);

        if (!keys.length) {
          return interaction.reply({ content: 'No keys found.', ephemeral: true });
        }

        const lines = keys.map(k => {
          const expired = k.expires_at && new Date(k.expires_at).getTime() < Date.now();
          return `${expired ? 'Expired' : 'Active'} ${maskKey(k.key)} - ${k.hwid ? 'HWID-Locked' : 'Open'}`;
        });

        const embed = new EmbedBuilder()
          .setColor(BRAND_COLOR)
          .setTitle('Keys')
          .setDescription(lines.join('\n'))
          .setTimestamp();

        await interaction.reply({ embeds: [embed], ephemeral: true });
      } else if (action === 'l') {
        const key = db.prepare(
          'SELECT key FROM keys WHERE script_id = ? AND user_id = ? ORDER BY created_at DESC LIMIT 1'
        ).get(scriptId, user.id);

        if (!key) {
          return interaction.reply({ content: 'No active key found.', ephemeral: true });
        }

        const loader = `loadstring(game:HttpGet("${publicBaseUrl()}/loader/${scriptId}?key=${key.key}"))()`;
        await interaction.reply({
          content: `📋 Loader:\n\`\`\`lua\n${loader}\n\`\`\``,
          ephemeral: true
        });
      } else if (action === 'h') {
        const modal = new ModalBuilder()
          .setCustomId(`hm_${scriptId}`)
          .setTitle('Reset HWID');

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
      }
    }

    if (interaction.isModalSubmit() && customId.startsWith('rm_')) {
      const scriptId = customId.substring(3);
      const keyVal = interaction.fields.getTextInputValue('key_input').toUpperCase();

      const keyRecord = db.prepare(
        'SELECT * FROM keys WHERE key = ? AND script_id = ? AND user_id = ?'
      ).get(keyVal, scriptId, user.id);

      if (!keyRecord) {
        return interaction.reply({ content: '❌ Invalid key', ephemeral: true });
      }

      if (keyRecord.expires_at && new Date(keyRecord.expires_at).getTime() < Date.now()) {
        return interaction.reply({ content: '❌ Key expired', ephemeral: true });
      }

      if (keyRecord.claimed_by) {
        return interaction.reply({ content: '❌ Key already claimed', ephemeral: true });
      }

      db.prepare(
        'UPDATE keys SET claimed_by = ?, claimed_tag = ?, used_count = used_count + 1, last_used_at = CURRENT_TIMESTAMP WHERE key = ?'
      ).run(user.id, interaction.user.tag, keyVal);

      await interaction.reply({
        content: '✅ Key redeemed successfully! The loader is now active.',
        ephemeral: true
      });
    }

    if (interaction.isModalSubmit() && customId.startsWith('hm_')) {
      const scriptId = customId.substring(3);
      const keyVal = interaction.fields.getTextInputValue('key_input').toUpperCase();

      const keyRecord = db.prepare(
        'SELECT * FROM keys WHERE key = ? AND script_id = ? AND user_id = ?'
      ).get(keyVal, scriptId, user.id);

      if (!keyRecord) {
        return interaction.reply({ content: '❌ Invalid key', ephemeral: true });
      }

      if (keyRecord.resettable_at) {
        const lastReset = new Date(keyRecord.resettable_at).getTime();
        const elapsed = Date.now() - lastReset;
        if (elapsed < COOLDOWN_HWID_RESET) {
          const remaining = COOLDOWN_HWID_RESET - elapsed;
          const hours = Math.floor(remaining / 3600000);
          const minutes = Math.floor((remaining % 3600000) / 60000);
          return interaction.reply({
            content: `⏳ Cooldown: ${hours}h ${minutes}m remaining`,
            ephemeral: true
          });
        }
      }

      db.prepare('UPDATE keys SET hwid = NULL, resettable_at = CURRENT_TIMESTAMP WHERE key = ?').run(keyVal);
      await interaction.reply({
        content: '✅ HWID reset successfully!',
        ephemeral: true
      });
    }
  } catch (error) {
    console.error('Interaction error:', error);
    await interaction.reply({
      content: '❌ Something went wrong',
      ephemeral: true
    });
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
