// server.js – KarmaForges v7.0 (Black & White Edition with Full Dashboard)

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
  REST,
  Routes,
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
const BRAND_COLOR = parseInt(process.env.BRAND_COLOR) || 0x000000;
const PREFIX = process.env.PREFIX || '/';
const COOLDOWN_HWID_RESET = 24 * 60 * 60 * 1000;

if (!DISCORD_TOKEN || !CLIENT_SECRET) {
  console.error('Missing DISCORD_TOKEN or CLIENT_SECRET.');
  process.exit(1);
}

console.log('⚫ KarmaForges v7.0 Black & White starting...');
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
  hwid TEXT,
  hwid_banned INTEGER DEFAULT 0,
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
  user_id TEXT,
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

CREATE TABLE IF NOT EXISTS obfuscation_logs (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  script_id TEXT NOT NULL,
  layers TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(script_id) REFERENCES scripts(id)
);

CREATE INDEX IF NOT EXISTS idx_keys_key ON keys(key);
CREATE INDEX IF NOT EXISTS idx_keys_script_id ON keys(script_id);
CREATE INDEX IF NOT EXISTS idx_scripts_user_id ON scripts(user_id);
CREATE INDEX IF NOT EXISTS idx_users_discord_id ON users(discord_id);
CREATE INDEX IF NOT EXISTS idx_users_hwid ON users(hwid);
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

function generateReferralCode() {
  return 'REF-' + crypto.randomBytes(4).toString('hex').toUpperCase();
}

function publicBaseUrl() { return PUBLIC_BASE_URL.replace(/\/$/, ''); }

function getSessionUser(req) { return req.session.user || null; }

function requireAuth(req, res, next) {
  if (req.session.user) return next();
  res.redirect('/');
}

function isOwner(user) {
  if (!user) return false;
  const emailMatch = user.email && OWNER_EMAILS.includes(user.email);
  const usernameMatch = user.username && OWNER_USERNAMES.includes(user.username);
  return emailMatch || usernameMatch || user.is_owner === 1;
}

function formatExpiry(e) {
  return e ? new Date(e).toLocaleDateString() + ' ' + new Date(e).toLocaleTimeString() : 'Permanent';
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
      scriptSrc: ["'self'", "'unsafe-inline'"],
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
  resave: true,
  saveUninitialized: true,
  cookie: {
    secure: PUBLIC_BASE_URL.startsWith('https'),
    maxAge: 7 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    sameSite: 'lax'
  }
}));

// ============ MULTER ============
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const user = req.session.user;
    if (!user) return cb(new Error('Not authenticated'), null);
    const userDir = path.join(__dirname, 'public/uploads', user.id);
    if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });
    cb(null, userDir);
  },
  filename: (req, file, cb) => {
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

// ============ DISCORD AUTH ============

const oauthStates = new Map();

app.get('/api/auth/discord', (req, res) => {
  const state = crypto.randomBytes(18).toString('hex');
  const expires = Date.now() + 5 * 60 * 1000;
  oauthStates.set(state, { expires });
  
  for (const [key, value] of oauthStates) {
    if (value.expires < Date.now()) oauthStates.delete(key);
  }
  
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

app.get('/api/auth/discord/callback', async (req, res) => {
  const { code, state } = req.query;
  
  if (!state || !oauthStates.has(state)) {
    return res.status(400).send('Invalid OAuth state. Please try again.');
  }
  
  const stateData = oauthStates.get(state);
  if (stateData.expires < Date.now()) {
    oauthStates.delete(state);
    return res.status(400).send('OAuth state expired. Please try again.');
  }
  
  oauthStates.delete(state);
  
  if (!code) {
    return res.status(400).send('No authorization code received');
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
    
    req.session.user = {
      id: dbUser.id,
      discord_id: user.id,
      username: user.username,
      avatar: user.avatar,
      email: dbUser.email,
      is_owner: isOwner(dbUser) ? 1 : 0,
      hwid: dbUser.hwid
    };
    
    req.session.save((err) => {
      if (err) console.error('Session save error:', err);
      const redirectUrl = `${publicBaseUrl()}/dashboard#user=${encodeURIComponent(user.username)}&id=${user.id}&avatar=${user.avatar || ''}`;
      res.redirect(redirectUrl);
    });
  } catch (e) {
    console.error('Auth error:', e);
    res.status(500).send('Authentication failed: ' + e.message);
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// ============ API ROUTES ============

app.get('/api/data', requireAuth, (req, res) => {
  const user = req.session.user;
  const scripts = db.prepare('SELECT * FROM scripts WHERE user_id = ? ORDER BY created_at DESC').all(user.id);
  const panels = db.prepare('SELECT * FROM panels WHERE user_id = ? ORDER BY created_at DESC').all(user.id);
  const keys = db.prepare('SELECT * FROM keys WHERE user_id = ? ORDER BY created_at DESC').all(user.id);
  const banned = db.prepare('SELECT * FROM banned_hwids ORDER BY created_at DESC').all();
  const userData = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
  res.json({ scripts, panels, keys, bannedHWIDs: banned, user: userData, serverTime: Date.now() });
});

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
  db.prepare(
    `INSERT INTO scripts (id, user_id, name, code, obfuscated_code, version, status, compress_mode, obfuscation_layers)
     VALUES (?, ?, ?, ?, ?, '1.0.0', 'active', ?, ?)`
  ).run(id, user.id, name, code, obfResult.code, compressMode ? 1 : 0, JSON.stringify(obfResult.layers));

  res.json({ success: true, id });
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
        .setColor(0x000000)
        .setTitle(`⬛ ${panel.name}`)
        .setDescription(panel.description || 'Use the buttons below to manage your script.')
        .addFields(
          { name: '📜 Script', value: `\`${db.prepare('SELECT name FROM scripts WHERE id = ?').get(panel.script_id)?.name || 'Unknown'}\``, inline: true },
          { name: '🔑 Status', value: '⬜ Active', inline: true }
        )
        .setFooter({ text: 'KarmaForges · Black & White' })
        .setTimestamp();

      const row1 = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId(`pv_${panel.script_id}`).setLabel('View Script').setStyle(ButtonStyle.Primary).setEmoji('👁️'),
        new ButtonBuilder().setCustomId(`pr_${panel.script_id}`).setLabel('Redeem Key').setStyle(ButtonStyle.Success).setEmoji('🔑')
      );

      const row2 = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId(`ki_${panel.script_id}`).setLabel('Key Info').setStyle(ButtonStyle.Secondary).setEmoji('ℹ️'),
        new ButtonBuilder().setCustomId(`gb_${panel.script_id}`).setLabel('Get Buyer Role').setStyle(ButtonStyle.Primary).setEmoji('🛒')
      );

      const row3 = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId(`ph_${panel.script_id}`).setLabel('Reset HWID').setStyle(ButtonStyle.Danger).setEmoji('🔄')
      );

      channel.send({ embeds: [embed], components: [row1, row2, row3] });
      res.json({ success: true });
    } else {
      res.status(400).json({ error: 'Channel not found' });
    }
  } else {
    res.status(503).json({ error: 'Discord bot not ready' });
  }
});

app.post('/api/generate-key', requireAuth, (req, res) => {
  const user = req.session.user;
  const { durationHours, panelId, note } = req.body;
  if (!panelId) return res.status(400).json({ error: 'Panel ID required' });

  const panel = db.prepare('SELECT * FROM panels WHERE id = ? AND user_id = ?').get(panelId, user.id);
  if (!panel) return res.status(404).json({ error: 'Panel not found' });

  const key = generateKey();
  const expiresAt = durationHours > 0 ? new Date(Date.now() + durationHours * 3600000).toISOString() : null;
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
      return res.status(429).json({ error: `Cooldown: ${hours}h ${minutes}m remaining` });
    }
  }

  db.prepare('UPDATE keys SET hwid = NULL, resettable_at = CURRENT_TIMESTAMP WHERE key = ?').run(key);
  res.json({ success: true });
});

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
  if (!script) return res.status(404).type('text/plain').send('-- Script not found');

  if (script.ffa_mode === 1) {
    return res.type('text/plain').send(`-- FFA Loader\nloadstring(game:HttpGet("${publicBaseUrl()}/api/script/${scriptId}"))()`);
  }

  if (!key) return res.status(403).type('text/plain').send('-- Missing key');

  const keyRecord = db.prepare('SELECT * FROM keys WHERE key = ? AND script_id = ?').get(key, scriptId);
  if (!keyRecord) return res.status(403).type('text/plain').send('-- Invalid key');
  if (keyRecord.expires_at && new Date(keyRecord.expires_at).getTime() < Date.now()) return res.status(403).type('text/plain').send('-- Key expired');
  if (keyRecord.max_uses > 0 && keyRecord.used_count >= keyRecord.max_uses) return res.status(403).type('text/plain').send('-- Key used maximum times');

  if (hwid) {
    const banned = db.prepare('SELECT * FROM banned_hwids WHERE hwid = ?').get(hwid);
    if (banned) return res.status(403).type('text/plain').send('-- HWID banned');
  }

  if (hwid) {
    if (!keyRecord.hwid) {
      db.prepare('UPDATE keys SET hwid = ?, last_used_at = CURRENT_TIMESTAMP WHERE key = ?').run(hwid, key);
    } else if (keyRecord.hwid !== hwid) {
      return res.status(403).type('text/plain').send('-- HWID mismatch');
    }
  }

  db.prepare('UPDATE keys SET used_count = used_count + 1, last_used_at = CURRENT_TIMESTAMP WHERE key = ?').run(key);
  res.type('text/plain').send(`-- Loader\nloadstring(game:HttpGet("${publicBaseUrl()}/api/script/${scriptId}?key=${key}&hwid=${hwid || ''}"))()`);
});

app.get('/api/script/:scriptId', (req, res) => {
  const { scriptId } = req.params;
  const { key, hwid } = req.query;

  const script = db.prepare('SELECT * FROM scripts WHERE id = ? AND status = "active"').get(scriptId);
  if (!script) return res.status(404).type('text/plain').send('-- Script not found');

  if (script.ffa_mode === 1) {
    res.setHeader('Cache-Control', 'no-store');
    return res.type('text/plain').send(script.obfuscated_code || script.code || '-- Empty');
  }

  if (!key) return res.status(403).type('text/plain').send('-- Missing key');

  const keyRecord = db.prepare('SELECT * FROM keys WHERE key = ? AND script_id = ?').get(key, scriptId);
  if (!keyRecord) return res.status(403).type('text/plain').send('-- Invalid key');
  if (keyRecord.expires_at && new Date(keyRecord.expires_at).getTime() < Date.now()) return res.status(403).type('text/plain').send('-- Key expired');
  if (keyRecord.max_uses > 0 && keyRecord.used_count >= keyRecord.max_uses) return res.status(403).type('text/plain').send('-- Key used maximum times');

  if (hwid) {
    const banned = db.prepare('SELECT * FROM banned_hwids WHERE hwid = ?').get(hwid);
    if (banned) return res.status(403).type('text/plain').send('-- HWID banned');
  }

  if (hwid && keyRecord.hwid && keyRecord.hwid !== hwid) return res.status(403).type('text/plain').send('-- HWID mismatch');
  if (hwid && !keyRecord.hwid) db.prepare('UPDATE keys SET hwid = ?, last_used_at = CURRENT_TIMESTAMP WHERE key = ?').run(hwid, key);

  db.prepare('UPDATE keys SET used_count = used_count + 1, last_used_at = CURRENT_TIMESTAMP WHERE key = ?').run(key);
  res.setHeader('Cache-Control', 'no-store');
  res.type('text/plain').send(script.obfuscated_code || script.code || '-- Empty');
});

// ============ FRONTEND ============

app.get('/', (req, res) => {
  res.send(indexHTML);
});

app.get('/dashboard', (req, res) => {
  res.send(indexHTML);
});

app.get('/dashboard/*', (req, res) => {
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
    activities: [{ name: 'KarmaForges · Black & White', type: ActivityType.Watching }]
  }
});

client.once('ready', () => {
  console.log(`⚫ Discord bot online as ${client.user.tag}`);
});

// ============ REGISTER SLASH COMMANDS ============

client.once('ready', async () => {
  try {
    const commands = [
      { name: 'help', description: 'Show all available commands' },
      { name: 'setup', description: 'Create or load your account' },
      { name: 'scripts', description: 'List all your scripts' },
      { name: 'keys', description: 'List all your keys' },
      {
        name: 'key',
        description: 'Generate a license key',
        options: [
          { name: 'script_id', description: 'The script ID', type: 3, required: true },
          { name: 'hours', description: 'Duration in hours (0 = permanent)', type: 4, required: false }
        ]
      },
      {
        name: 'reset-hwid',
        description: 'Reset HWID for a key (24h cooldown)',
        options: [
          { name: 'key', description: 'The key to reset', type: 3, required: true }
        ]
      },
      {
        name: 'resethwid-user',
        description: 'Reset HWID for a specific user (owner only)',
        options: [
          { name: 'user', description: 'The user to reset HWID for', type: 6, required: true }
        ]
      },
      {
        name: 'panelsetup',
        description: 'Create a Discord panel for your script',
        options: [
          { name: 'script_name', description: 'The name of your script', type: 3, required: true },
          { name: 'title', description: 'Panel title (default: script name)', type: 3, required: false },
          { name: 'description', description: 'Panel description', type: 3, required: false }
        ]
      },
      {
        name: 'whitelist',
        description: 'Whitelist a user for your script',
        options: [
          { name: 'script_id', description: 'Script ID', type: 3, required: true },
          { name: 'user', description: 'User to whitelist', type: 6, required: true },
          { name: 'hours', description: 'Duration in hours', type: 4, required: false }
        ]
      },
      {
        name: 'banhwid-user',
        description: 'Ban a user\'s HWID (owner only)',
        options: [
          { name: 'user', description: 'The user to ban', type: 6, required: true },
          { name: 'reason', description: 'Reason for the ban', type: 3, required: false }
        ]
      },
      {
        name: 'banhwid',
        description: 'Ban an HWID directly (owner only)',
        options: [
          { name: 'hwid', description: 'HWID to ban', type: 3, required: true }
        ]
      },
      {
        name: 'unbanhwid',
        description: 'Unban an HWID (owner only)',
        options: [
          { name: 'hwid', description: 'HWID to unban', type: 3, required: true }
        ]
      }
    ];

    const rest = new REST({ version: '10' }).setToken(DISCORD_TOKEN);
    await rest.put(Routes.applicationCommands(CLIENT_ID), { body: commands });
    console.log('✅ All slash commands registered successfully!');
  } catch (error) {
    console.error('❌ Failed to register slash commands:', error);
  }
});

// ============ HANDLE SLASH COMMANDS ============

client.on('interactionCreate', async (interaction) => {
  if (!interaction.isChatInputCommand()) return;

  const { commandName, options } = interaction;
  const user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(interaction.user.id);

  try {
    if (commandName === 'help') {
      const embed = new EmbedBuilder()
        .setColor(0x000000)
        .setTitle('⬛ KarmaForges – Commands')
        .setDescription([
          '**📋 General**',
          '/setup – Create/load account',
          '/scripts – List your scripts',
          '/keys – List your keys',
          '',
          '**🔑 Key Management**',
          '/key <script_id> [hours] – Generate key',
          '/reset-hwid <key> – Reset HWID (24h cooldown)',
          '/resethwid-user <@user> – Reset user\'s HWID (owner)',
          '',
          '**📦 Panel Setup**',
          '/panelsetup <script_name> [title] [description] – Create Discord panel',
          '',
          '**👥 Whitelist**',
          '/whitelist <script_id> <@user> [hours] – Whitelist user',
          '',
          '**🚫 HWID Bans (Owner)**',
          '/banhwid-user <@user> [reason] – Ban user\'s HWID',
          '/banhwid <hwid> – Ban HWID directly',
          '/unbanhwid <hwid> – Unban HWID'
        ].join('\n'))
        .setFooter({ text: 'KarmaForges · Black & White' })
        .setTimestamp();

      await interaction.reply({ embeds: [embed] });
      return;
    }

    if (commandName === 'setup') {
      let dbUser = user;
      if (!dbUser) {
        const id = makeId('user');
        const referralCode = generateReferralCode();
        db.prepare(
          `INSERT INTO users (id, discord_id, username, avatar, referral_code)
           VALUES (?, ?, ?, ?, ?)`
        ).run(id, interaction.user.id, interaction.user.username, interaction.user.displayAvatarURL() || '', referralCode);
        dbUser = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(interaction.user.id);
      }

      const sc = db.prepare('SELECT COUNT(*) as count FROM scripts WHERE user_id = ?').get(dbUser.id);
      const kc = db.prepare('SELECT COUNT(*) as count FROM keys WHERE user_id = ?').get(dbUser.id);

      const embed = new EmbedBuilder()
        .setColor(0x000000)
        .setTitle('⬜ Account Ready')
        .setDescription(`Welcome ${interaction.user.username}!`)
        .addFields(
          { name: '📜 Scripts', value: String(sc.count), inline: true },
          { name: '🔑 Keys', value: String(kc.count), inline: true },
          { name: '💰 Credits', value: String(dbUser.credits || 0), inline: true }
        )
        .setFooter({ text: 'KarmaForges' })
        .setTimestamp();

      await interaction.reply({ embeds: [embed] });
      return;
    }

    if (commandName === 'scripts') {
      if (!user) return interaction.reply({ content: 'Use /setup first', ephemeral: true });

      const scripts = db.prepare('SELECT * FROM scripts WHERE user_id = ? ORDER BY created_at DESC').all(user.id);
      if (!scripts.length) return interaction.reply({ content: '📂 No scripts found.', ephemeral: true });

      const embed = new EmbedBuilder()
        .setColor(0x000000)
        .setTitle(`📜 Your Scripts (${scripts.length})`)
        .setDescription(scripts.map((s, i) =>
          `${i + 1}. **${s.name}** \`${s.id}\` - ${s.status === 'active' ? '⬜ Active' : '⬛ Disabled'}`
        ).join('\n'))
        .setTimestamp();

      await interaction.reply({ embeds: [embed] });
      return;
    }

    if (commandName === 'keys') {
      if (!user) return interaction.reply({ content: 'Use /setup first', ephemeral: true });

      const keys = db.prepare('SELECT * FROM keys WHERE user_id = ? ORDER BY created_at DESC').all(user.id);
      if (!keys.length) return interaction.reply({ content: '🔑 No keys found.', ephemeral: true });

      const embed = new EmbedBuilder()
        .setColor(0x000000)
        .setTitle(`🔑 Your Keys (${keys.length})`)
        .setDescription(keys.map(k => {
          const expired = k.expires_at && new Date(k.expires_at).getTime() < Date.now();
          return `\`${k.key}\` - ${expired ? '❌ Expired' : '✅ Active'} - ${k.hwid ? '🔒 Locked' : '🔓 Open'}`;
        }).join('\n'))
        .setTimestamp();

      await interaction.reply({ embeds: [embed] });
      return;
    }

    if (commandName === 'key') {
      if (!user) return interaction.reply({ content: 'Use /setup first', ephemeral: true });

      const scriptId = options.getString('script_id');
      const hours = options.getInteger('hours') || 0;

      const script = db.prepare('SELECT * FROM scripts WHERE id = ? AND user_id = ?').get(scriptId, user.id);
      if (!script) return interaction.reply({ content: '❌ Script not found', ephemeral: true });

      const key = generateKey();
      const expiresAt = hours > 0 ? new Date(Date.now() + hours * 3600000).toISOString() : null;
      const id = makeId('key');

      db.prepare(
        `INSERT INTO keys (id, script_id, user_id, key, expires_at, max_uses)
         VALUES (?, ?, ?, ?, ?, 1)`
      ).run(id, scriptId, user.id, key, expiresAt);

      const embed = new EmbedBuilder()
        .setColor(0x000000)
        .setTitle('🔑 Key Generated')
        .setDescription(`**Script:** ${script.name}`)
        .addFields(
          { name: 'Key', value: `\`${key}\``, inline: false },
          { name: 'Expires', value: expiresAt ? formatExpiry(expiresAt) : 'Permanent', inline: true }
        )
        .setTimestamp();

      await interaction.reply({ embeds: [embed] });
      return;
    }

    if (commandName === 'reset-hwid') {
      if (!user) return interaction.reply({ content: 'Use /setup first', ephemeral: true });

      const key = options.getString('key');
      const keyRecord = db.prepare('SELECT * FROM keys WHERE key = ? AND user_id = ?').get(key, user.id);
      if (!keyRecord) return interaction.reply({ content: '❌ Key not found', ephemeral: true });

      if (keyRecord.resettable_at) {
        const lastReset = new Date(keyRecord.resettable_at).getTime();
        const elapsed = Date.now() - lastReset;
        if (elapsed < COOLDOWN_HWID_RESET) {
          const remaining = COOLDOWN_HWID_RESET - elapsed;
          const hours = Math.floor(remaining / 3600000);
          const minutes = Math.floor((remaining % 3600000) / 60000);
          return interaction.reply({ content: `⏳ Cooldown: ${hours}h ${minutes}m remaining`, ephemeral: true });
        }
      }

      db.prepare('UPDATE keys SET hwid = NULL, resettable_at = CURRENT_TIMESTAMP WHERE key = ?').run(key);
      await interaction.reply({ content: `✅ HWID reset for \`${key}\`` });
      return;
    }

    if (commandName === 'resethwid-user') {
      if (!isOwner(user)) return interaction.reply({ content: '❌ Owner only command', ephemeral: true });

      const targetUser = options.getUser('user');
      const target = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(targetUser.id);
      if (!target) return interaction.reply({ content: '❌ User not found in database', ephemeral: true });

      db.prepare('UPDATE users SET hwid = NULL WHERE id = ?').run(target.id);
      db.prepare('UPDATE keys SET hwid = NULL, resettable_at = CURRENT_TIMESTAMP WHERE user_id = ?').run(target.id);

      await interaction.reply({ content: `✅ HWID reset for ${targetUser} (\`${targetUser.id}\`)` });
      return;
    }

    if (commandName === 'panelsetup') {
      if (!user) return interaction.reply({ content: 'Use /setup first', ephemeral: true });

      const scriptName = options.getString('script_name');
      const title = options.getString('title') || scriptName;
      const description = options.getString('description') || 'Use the buttons below to manage your script.';

      const script = db.prepare('SELECT * FROM scripts WHERE user_id = ? AND name = ?').get(user.id, scriptName);
      if (!script) return interaction.reply({ content: `❌ Script "${scriptName}" not found`, ephemeral: true });

      const panelId = makeId('panel');
      db.prepare(
        `INSERT INTO panels (id, user_id, name, description, channel_id, script_id)
         VALUES (?, ?, ?, ?, ?, ?)`
      ).run(panelId, user.id, title, description, interaction.channelId, script.id);

      const embed = new EmbedBuilder()
        .setColor(0x000000)
        .setTitle(`⬛ ${title}`)
        .setDescription(description)
        .addFields(
          { name: '📜 Script', value: `\`${script.name}\``, inline: true },
          { name: '📌 Version', value: `\`${script.version || '1.0.0'}\``, inline: true },
          { name: '🔑 Status', value: script.status === 'active' ? '⬜ Active' : '⬛ Disabled', inline: true }
        )
        .setFooter({ text: 'KarmaForges · Black & White' })
        .setTimestamp();

      const row1 = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId(`pv_${script.id}`).setLabel('View Script').setStyle(ButtonStyle.Primary).setEmoji('👁️'),
        new ButtonBuilder().setCustomId(`pr_${script.id}`).setLabel('Redeem Key').setStyle(ButtonStyle.Success).setEmoji('🔑')
      );

      const row2 = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId(`ki_${script.id}`).setLabel('Key Info').setStyle(ButtonStyle.Secondary).setEmoji('ℹ️'),
        new ButtonBuilder().setCustomId(`gb_${script.id}`).setLabel('Get Buyer Role').setStyle(ButtonStyle.Primary).setEmoji('🛒')
      );

      const row3 = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId(`ph_${script.id}`).setLabel('Reset HWID').setStyle(ButtonStyle.Danger).setEmoji('🔄')
      );

      await interaction.reply({ embeds: [embed], components: [row1, row2, row3] });
      return;
    }

    if (commandName === 'whitelist') {
      if (!user) return interaction.reply({ content: 'Use /setup first', ephemeral: true });

      const scriptId = options.getString('script_id');
      const targetUser = options.getUser('user');
      const hours = options.getInteger('hours') || 0;

      const script = db.prepare('SELECT * FROM scripts WHERE id = ? AND user_id = ?').get(scriptId, user.id);
      if (!script) return interaction.reply({ content: '❌ Script not found', ephemeral: true });

      let target = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(targetUser.id);
      if (!target) {
        const id = makeId('user');
        db.prepare(`INSERT INTO users (id, discord_id, username) VALUES (?, ?, ?)`).run(id, targetUser.id, targetUser.username);
        target = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(targetUser.id);
      }

      const key = generateKey();
      const expiresAt = hours > 0 ? new Date(Date.now() + hours * 3600000).toISOString() : null;

      db.prepare(
        `INSERT INTO keys (id, script_id, user_id, key, expires_at, max_uses)
         VALUES (?, ?, ?, ?, ?, 1)`
      ).run(makeId('key'), scriptId, target.id, key, expiresAt);

      await interaction.reply({ content: `✅ ${targetUser} whitelisted for **${script.name}** with key \`${key}\`` });
      return;
    }

    if (commandName === 'banhwid-user') {
      if (!isOwner(user)) return interaction.reply({ content: '❌ Owner only command', ephemeral: true });

      const targetUser = options.getUser('user');
      const reason = options.getString('reason') || 'No reason provided';

      const target = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(targetUser.id);
      if (!target) return interaction.reply({ content: '❌ User not found in database', ephemeral: true });

      if (!target.hwid) return interaction.reply({ content: `❌ ${targetUser} has no HWID registered`, ephemeral: true });

      db.prepare(
        'INSERT OR REPLACE INTO banned_hwids (hwid, user_id, reason, banned_by) VALUES (?, ?, ?, ?)'
      ).run(target.hwid, target.id, reason, interaction.user.id);

      db.prepare('UPDATE users SET hwid_banned = 1 WHERE id = ?').run(target.id);

      await interaction.reply({ 
        content: `✅ ${targetUser} has been HWID banned!\n**HWID:** \`${target.hwid}\`\n**Reason:** ${reason}` 
      });
      return;
    }

    if (commandName === 'banhwid') {
      if (!isOwner(user)) return interaction.reply({ content: '❌ Owner only command', ephemeral: true });

      const hwid = options.getString('hwid');
      db.prepare('INSERT OR REPLACE INTO banned_hwids (hwid, banned_by) VALUES (?, ?)').run(hwid, interaction.user.id);
      await interaction.reply({ content: `✅ HWID \`${hwid}\` banned` });
      return;
    }

    if (commandName === 'unbanhwid') {
      if (!isOwner(user)) return interaction.reply({ content: '❌ Owner only command', ephemeral: true });

      const hwid = options.getString('hwid');
      db.prepare('DELETE FROM banned_hwids WHERE hwid = ?').run(hwid);
      db.prepare('UPDATE users SET hwid_banned = 0 WHERE hwid = ?').run(hwid);
      
      await interaction.reply({ content: `✅ HWID \`${hwid}\` unbanned` });
      return;
    }

    await interaction.reply({ content: '❌ Unknown command', ephemeral: true });
  } catch (error) {
    console.error('Command error:', error);
    await interaction.reply({ content: '❌ Something went wrong', ephemeral: true });
  }
});

// ============ BUTTON INTERACTIONS ============

client.on('interactionCreate', async (interaction) => {
  if (!interaction.isButton()) return;

  const customId = interaction.customId;
  const action = customId.slice(0, 2);
  const scriptId = customId.slice(3);

  try {
    const user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(interaction.user.id);
    if (!user) return interaction.reply({ content: 'Use /setup first', ephemeral: true });

    const script = db.prepare('SELECT * FROM scripts WHERE id = ?').get(scriptId);
    if (!script) return interaction.reply({ content: '❌ Script not found', ephemeral: true });

    if (action === 'pv') {
      const keys = db.prepare('SELECT COUNT(*) as count FROM keys WHERE script_id = ?').get(scriptId);
      const embed = new EmbedBuilder()
        .setColor(0x000000)
        .setTitle(`⬛ ${script.name}`)
        .addFields(
          { name: 'Version', value: script.version || '1.0.0', inline: true },
          { name: 'Status', value: script.status === 'active' ? '⬜ Active' : '⬛ Disabled', inline: true },
          { name: 'Keys Generated', value: String(keys.count), inline: true },
          { name: 'FFA Mode', value: script.ffa_mode ? '✅ Enabled' : '❌ Disabled', inline: true }
        )
        .setFooter({ text: 'KarmaForges' })
        .setTimestamp();

      await interaction.reply({ embeds: [embed], ephemeral: true });
      return;
    }

    if (action === 'pr') {
      const modal = new ModalBuilder()
        .setCustomId(`rm_${scriptId}`)
        .setTitle('Redeem License Key');

      modal.addComponents(
        new ActionRowBuilder().addComponents(
          new TextInputBuilder()
            .setCustomId('key_input')
            .setLabel('Enter your license key')
            .setStyle(TextInputStyle.Short)
            .setRequired(true)
            .setPlaceholder('KARMA-XXXX-XXXX-XXXX')
        )
      );

      await interaction.showModal(modal);
      return;
    }

    if (action === 'ki') {
      const keys = db.prepare('SELECT * FROM keys WHERE script_id = ? AND user_id = ? ORDER BY created_at DESC LIMIT 5').all(scriptId, user.id);
      if (!keys.length) return interaction.reply({ content: '🔑 No keys found for this script.', ephemeral: true });

      const embed = new EmbedBuilder()
        .setColor(0x000000)
        .setTitle(`🔑 Key Info - ${script.name}`)
        .setDescription(keys.map(k => {
          const expired = k.expires_at && new Date(k.expires_at).getTime() < Date.now();
          return `\`${k.key}\` - ${expired ? '❌ Expired' : '✅ Active'} - ${k.hwid ? '🔒 Locked' : '🔓 Open'}`;
        }).join('\n'))
        .setFooter({ text: 'Showing latest 5 keys' })
        .setTimestamp();

      await interaction.reply({ embeds: [embed], ephemeral: true });
      return;
    }

    if (action === 'gb') {
      await interaction.reply({ 
        content: '🛒 To get the buyer role, please contact support with your key.\nIf you already have a key, use the **Redeem Key** button first.',
        ephemeral: true 
      });
      return;
    }

    if (action === 'ph') {
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
            .setPlaceholder('KARMA-XXXX-XXXX-XXXX')
        )
      );

      await interaction.showModal(modal);
      return;
    }
  } catch (error) {
    console.error('Button error:', error);
    await interaction.reply({ content: '❌ Something went wrong', ephemeral: true });
  }
});

// ============ MODAL SUBMISSIONS ============

client.on('interactionCreate', async (interaction) => {
  if (!interaction.isModalSubmit()) return;

  const customId = interaction.customId;

  try {
    const user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(interaction.user.id);
    if (!user) return interaction.reply({ content: 'Use /setup first', ephemeral: true });

    if (customId.startsWith('rm_')) {
      const scriptId = customId.slice(3);
      const keyVal = interaction.fields.getTextInputValue('key_input').toUpperCase();

      const keyRecord = db.prepare('SELECT * FROM keys WHERE key = ? AND script_id = ?').get(keyVal, scriptId);
      if (!keyRecord) return interaction.reply({ content: '❌ Invalid key', ephemeral: true });

      if (keyRecord.expires_at && new Date(keyRecord.expires_at).getTime() < Date.now()) {
        return interaction.reply({ content: '❌ Key expired', ephemeral: true });
      }

      if (keyRecord.claimed_by) {
        return interaction.reply({ content: '❌ Key already claimed', ephemeral: true });
      }

      db.prepare(
        'UPDATE keys SET claimed_by = ?, claimed_tag = ?, used_count = used_count + 1, last_used_at = CURRENT_TIMESTAMP WHERE key = ?'
      ).run(user.id, interaction.user.tag, keyVal);

      await interaction.reply({ content: '✅ Key redeemed successfully!', ephemeral: true });
      return;
    }

    if (customId.startsWith('hm_')) {
      const scriptId = customId.slice(3);
      const keyVal = interaction.fields.getTextInputValue('key_input').toUpperCase();

      const keyRecord = db.prepare('SELECT * FROM keys WHERE key = ? AND script_id = ? AND user_id = ?').get(keyVal, scriptId, user.id);
      if (!keyRecord) return interaction.reply({ content: '❌ Invalid key', ephemeral: true });

      if (keyRecord.resettable_at) {
        const lastReset = new Date(keyRecord.resettable_at).getTime();
        const elapsed = Date.now() - lastReset;
        if (elapsed < COOLDOWN_HWID_RESET) {
          const remaining = COOLDOWN_HWID_RESET - elapsed;
          const hours = Math.floor(remaining / 3600000);
          const minutes = Math.floor((remaining % 3600000) / 60000);
          return interaction.reply({ content: `⏳ Cooldown: ${hours}h ${minutes}m remaining`, ephemeral: true });
        }
      }

      db.prepare('UPDATE keys SET hwid = NULL, resettable_at = CURRENT_TIMESTAMP WHERE key = ?').run(keyVal);
      await interaction.reply({ content: '✅ HWID reset successfully!', ephemeral: true });
      return;
    }
  } catch (error) {
    console.error('Modal error:', error);
    await interaction.reply({ content: '❌ Something went wrong', ephemeral: true });
  }
});

// ============ START SERVER ============

const port = Number(process.env.PORT || 3000);

(async () => {
  try {
    app.listen(port, '0.0.0.0', () => {
      console.log(`⚫ KarmaForges v7.0 running on port ${port}`);
      console.log(`🌐 Website: ${publicBaseUrl()}`);
    });
  } catch (e) {
    console.error('Startup failed:', e);
  }

  await client.login(DISCORD_TOKEN);
})();

// ====================================================================
// ============ EMBEDDED BLACK & WHITE INDEX.HTML ============
// ====================================================================

const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>KarmaForges · Black & White</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>⚫</text></svg>" />
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@100;200;300;400;500;600;700;800;900&family=JetBrains+Mono:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        *,
        *::before,
        *::after {
            box-sizing: border-box;
        }

        :root {
            --bg: #000000;
            --surface: #0a0a0a;
            --surface2: #111111;
            --surface3: #1a1a1a;
            --border: rgba(255, 255, 255, 0.06);
            --border2: rgba(255, 255, 255, 0.12);
            --text: #ffffff;
            --text2: rgba(255, 255, 255, 0.7);
            --text3: rgba(255, 255, 255, 0.4);
            --accent: #ffffff;
            --accent2: rgba(255, 255, 255, 0.08);
            --radius: 12px;
            --radius2: 8px;
            --transition: 0.2s ease;
        }

        body {
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 0;
            min-height: 100vh;
            -webkit-font-smoothing: antialiased;
            overflow: hidden;
        }

        ::selection {
            background: #ffffff;
            color: #000000;
        }

        /* --- AUTH WRAPPER --- */
        #auth-wrapper {
            position: fixed;
            inset: 0;
            background: var(--bg);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 9999;
            padding: 20px;
        }

        .auth-card {
            background: var(--surface);
            border: 1px solid var(--border2);
            border-radius: var(--radius);
            padding: 48px 40px;
            max-width: 400px;
            width: 100%;
            text-align: center;
        }

        .auth-card .logo {
            font-size: 24px;
            font-weight: 800;
            letter-spacing: -0.5px;
            margin-bottom: 4px;
        }

        .auth-card .logo span {
            color: rgba(255, 255, 255, 0.3);
        }

        .auth-card .sub {
            color: var(--text3);
            font-size: 13px;
            margin-bottom: 28px;
        }

        .auth-card .btn-discord {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            width: 100%;
            padding: 14px;
            background: #ffffff;
            color: #000000;
            border: none;
            border-radius: var(--radius2);
            font-family: 'Inter', sans-serif;
            font-weight: 600;
            font-size: 14px;
            cursor: pointer;
            text-decoration: none;
            transition: all var(--transition);
        }

        .auth-card .btn-discord:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 20px rgba(255, 255, 255, 0.15);
        }

        .auth-card .btn-discord svg {
            width: 20px;
            height: 20px;
            fill: #000;
        }

        /* --- DASHBOARD --- */
        #dashboard-content {
            display: none;
            min-height: 100vh;
            flex-direction: row;
        }

        /* --- SIDEBAR --- */
        .sidebar {
            width: 240px;
            background: var(--surface);
            border-right: 1px solid var(--border);
            padding: 24px 16px;
            height: 100vh;
            position: sticky;
            top: 0;
            overflow-y: auto;
            flex-shrink: 0;
        }

        .sidebar::-webkit-scrollbar {
            width: 3px;
        }
        .sidebar::-webkit-scrollbar-thumb {
            background: var(--border2);
            border-radius: 4px;
        }

        .sidebar .brand {
            font-size: 18px;
            font-weight: 800;
            letter-spacing: -0.5px;
            padding: 0 8px 20px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 16px;
        }

        .sidebar .brand span {
            color: rgba(255, 255, 255, 0.3);
        }

        .sidebar .nav-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 12px;
            border-radius: var(--radius2);
            color: var(--text3);
            font-weight: 500;
            font-size: 13px;
            cursor: pointer;
            transition: all var(--transition);
            text-decoration: none;
            border: none;
            background: none;
            width: 100%;
            text-align: left;
        }

        .sidebar .nav-item:hover {
            color: var(--text);
            background: var(--accent2);
        }

        .sidebar .nav-item.active {
            color: var(--text);
            background: var(--accent2);
        }

        .sidebar .nav-item .icon {
            width: 18px;
            height: 18px;
            flex-shrink: 0;
        }

        /* --- MAIN --- */
        .main {
            flex: 1;
            padding: 32px 40px;
            overflow-y: auto;
            height: 100vh;
        }

        .main::-webkit-scrollbar {
            width: 4px;
        }
        .main::-webkit-scrollbar-thumb {
            background: var(--border2);
            border-radius: 4px;
        }

        .main .topbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 32px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border);
        }

        .main .topbar .user {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .main .topbar .user .avatar {
            width: 36px;
            height: 36px;
            border-radius: 50%;
            background: var(--surface2);
            border: 1px solid var(--border2);
            object-fit: cover;
        }

        .main .topbar .user .name {
            font-weight: 600;
            font-size: 14px;
        }

        .main .topbar .user .logout {
            color: var(--text3);
            font-size: 12px;
            cursor: pointer;
            background: none;
            border: none;
            font-family: 'Inter', sans-serif;
            transition: color var(--transition);
        }

        .main .topbar .user .logout:hover {
            color: var(--text);
        }

        .main .topbar .invite {
            padding: 8px 16px;
            background: var(--text);
            color: var(--bg);
            border: none;
            border-radius: var(--radius2);
            font-weight: 600;
            font-size: 12px;
            cursor: pointer;
            text-decoration: none;
            transition: all var(--transition);
            font-family: 'Inter', sans-serif;
        }

        .main .topbar .invite:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 16px rgba(255, 255, 255, 0.15);
        }

        /* --- VIEW SECTIONS --- */
        .view-section {
            display: none;
            animation: fadeIn 0.25s ease;
        }

        .view-section.active {
            display: block;
        }

        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(8px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .view-section h2 {
            font-size: 20px;
            font-weight: 700;
            margin-bottom: 20px;
            letter-spacing: -0.3px;
        }

        .view-section h2 span {
            color: rgba(255, 255, 255, 0.3);
        }

        /* --- CARDS --- */
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 24px;
            margin-bottom: 20px;
        }

        .card .flex {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            align-items: center;
        }

        .card .flex .grow {
            flex: 1;
            min-width: 180px;
        }

        /* --- INPUTS --- */
        input,
        textarea,
        select {
            background: var(--surface2);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 10px 14px;
            border-radius: var(--radius2);
            font-family: 'Inter', sans-serif;
            font-size: 13px;
            width: 100%;
            transition: all var(--transition);
            outline: none;
        }

        input:focus,
        textarea:focus,
        select:focus {
            border-color: rgba(255, 255, 255, 0.3);
        }

        textarea {
            resize: vertical;
            min-height: 120px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            line-height: 1.6;
        }

        select {
            appearance: none;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='rgba(255,255,255,0.3)' d='M6 8L1 3h10z'/%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-position: right 12px center;
            padding-right: 36px;
            cursor: pointer;
        }

        select option {
            background: var(--surface);
            color: var(--text);
        }

        /* --- BUTTONS --- */
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: var(--radius2);
            font-family: 'Inter', sans-serif;
            font-weight: 600;
            font-size: 13px;
            cursor: pointer;
            transition: all var(--transition);
            display: inline-flex;
            align-items: center;
            gap: 8px;
            text-decoration: none;
        }

        .btn-primary {
            background: var(--text);
            color: var(--bg);
        }

        .btn-primary:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 16px rgba(255, 255, 255, 0.15);
        }

        .btn-danger {
            background: rgba(255, 255, 255, 0.06);
            color: rgba(255, 255, 255, 0.7);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .btn-danger:hover {
            background: rgba(255, 255, 255, 0.1);
            color: #fff;
        }

        .btn-outline {
            background: transparent;
            color: var(--text2);
            border: 1px solid var(--border);
        }

        .btn-outline:hover {
            border-color: rgba(255, 255, 255, 0.3);
            color: var(--text);
        }

        .btn-success {
            background: rgba(255, 255, 255, 0.06);
            color: rgba(255, 255, 255, 0.7);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .btn-success:hover {
            background: rgba(255, 255, 255, 0.1);
            color: #fff;
        }

        .btn-sm {
            padding: 6px 14px;
            font-size: 12px;
        }

        /* --- CHECKBOX --- */
        .checkbox-container {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 13px;
            color: var(--text2);
            cursor: pointer;
            padding: 8px 12px;
            background: var(--surface2);
            border: 1px solid var(--border);
            border-radius: var(--radius2);
            transition: all var(--transition);
        }

        .checkbox-container:hover {
            border-color: rgba(255, 255, 255, 0.2);
        }

        .checkbox-container input {
            width: 16px;
            height: 16px;
            accent-color: #fff;
            cursor: pointer;
            flex-shrink: 0;
        }

        /* --- GRIDS --- */
        .scripts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
            gap: 16px;
        }

        .script-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 16px;
            transition: all var(--transition);
        }

        .script-card:hover {
            border-color: rgba(255, 255, 255, 0.15);
            transform: translateY(-2px);
        }

        .script-card .title {
            font-weight: 600;
            font-size: 14px;
            margin-bottom: 6px;
        }

        .script-card .meta {
            color: var(--text3);
            font-size: 12px;
            margin-bottom: 12px;
        }

        .script-card .actions {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }

        .script-card .actions .btn {
            flex: 1;
            justify-content: center;
            font-size: 11px;
            padding: 8px 12px;
        }

        /* --- BADGES --- */
        .badge {
            display: inline-block;
            padding: 2px 10px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .badge-active {
            background: rgba(255, 255, 255, 0.1);
            color: #fff;
        }

        .badge-disabled {
            background: rgba(255, 255, 255, 0.04);
            color: var(--text3);
        }

        .badge-ffa {
            background: rgba(255, 255, 255, 0.06);
            color: var(--text2);
        }

        /* --- STATS --- */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 12px;
            margin-top: 16px;
        }

        .stat {
            background: var(--surface2);
            border: 1px solid var(--border);
            border-radius: var(--radius2);
            padding: 16px;
            text-align: center;
        }

        .stat .num {
            font-size: 24px;
            font-weight: 700;
        }

        .stat .label {
            color: var(--text3);
            font-size: 11px;
            margin-top: 2px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        /* --- LOADER INPUT --- */
        .loader-input {
            background: var(--surface2) !important;
            border: 1px dashed var(--border) !important;
            cursor: copy;
            color: var(--text2) !important;
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 12px;
            text-align: center;
        }

        /* --- MOBILE --- */
        .sidebar-overlay {
            display: none;
        }

        .mobile-brand {
            display: none;
        }

        .menu-toggle {
            display: none;
            background: none;
            border: none;
            color: var(--text);
            font-size: 24px;
            cursor: pointer;
        }

        @media (max-width: 768px) {
            .sidebar {
                display: none;
                position: fixed;
                inset: 0;
                width: 280px;
                z-index: 100;
                background: var(--bg);
                border-right: 1px solid var(--border);
                padding-top: 60px;
            }

            .sidebar.open {
                display: block;
            }

            .sidebar-overlay {
                display: block;
                position: fixed;
                inset: 0;
                background: rgba(0, 0, 0, 0.8);
                z-index: 99;
            }

            .sidebar-overlay.open {
                display: block;
            }

            .menu-toggle {
                display: block;
            }

            .mobile-brand {
                display: flex;
                justify-content: space-between;
                align-items: center;
                width: 100%;
            }

            .main {
                padding: 20px 16px;
            }

            .topbar {
                flex-direction: column;
                align-items: stretch !important;
                gap: 12px;
            }

            .topbar .user {
                justify-content: space-between;
            }

            .scripts-grid {
                grid-template-columns: 1fr;
            }

            .card .flex {
                flex-direction: column;
            }

            .card .flex .grow {
                width: 100%;
                min-width: auto;
            }
        }
    </style>
</head>
<body>

    <!-- ===== AUTH WRAPPER ===== -->
    <div id="auth-wrapper">
        <div class="auth-card">
            <div class="logo">KARMA<span>FORGES</span></div>
            <div class="sub">Black & White · Script Protection</div>
            <a href="/api/auth/discord" class="btn-discord">
                <svg viewBox="0 0 127.14 96.36"><path d="M107.7,8.07A105.15,105.15,0,0,0,81.47,0a72.06,72.06,0,0,0-3.36,6.83A97.68,97.68,0,0,0,49,6.83,72.37,72.37,0,0,0,45.64,0,105.89,105.89,0,0,0,19.39,8.09C2.79,32.65-1.71,56.6.54,80.21h0A105.73,105.73,0,0,0,32.71,96.36,77.7,77.7,0,0,0,39.6,85.25a68.42,68.42,0,0,1-10.85-5.18c.91-.66,1.8-1.34,2.66-2a75.57,75.57,0,0,0,64.32,0c.87.71,1.76,1.39,2.66,2a68.68,68.68,0,0,1-10.87,5.19,77,77,0,0,0,6.89,11.1A105.25,105.25,0,0,0,126.6,80.22h0C129.24,52.84,122.09,29.11,107.7,8.07ZM42.45,65.69C36.18,65.69,31,60,31,53s5-12.74,11.43-12.74S54,46,53.89,53,48.84,65.69,42.45,65.69Zm42.24,0C78.41,65.69,73.31,60,73.31,53s5-12.74,11.43-12.74S96.1,46,96,53,91.08,65.69,84.69,65.69Z"/></svg>
                Login with Discord
            </a>
        </div>
    </div>

    <!-- ===== DASHBOARD ===== -->
    <div id="dashboard-content">
        <div class="sidebar-overlay" id="sidebarOverlay" onclick="closeSidebar()"></div>

        <aside class="sidebar" id="sidebar">
            <div class="brand">KARMA<span>FORGES</span></div>
            <button class="nav-item active" onclick="switchView('overview', this)">
                <svg class="icon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"/></svg>
                Overview
            </button>
            <button class="nav-item" onclick="switchView('scripts', this)">
                <svg class="icon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/></svg>
                Scripts
            </button>
            <button class="nav-item" onclick="switchView('panels', this)">
                <svg class="icon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>
                Panels
            </button>
            <button class="nav-item" onclick="switchView('keys', this)">
                <svg class="icon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/></svg>
                Keys
            </button>
            <button class="nav-item" onclick="switchView('hwids', this)">
                <svg class="icon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"/></svg>
                HWID Bans
            </button>
            <button class="nav-item" onclick="switchView('settings', this)">
                <svg class="icon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
                Settings
            </button>
        </aside>

        <main class="main">
            <!-- Topbar -->
            <div class="topbar">
                <div class="mobile-brand">
                    <span style="font-weight:700;font-size:16px;">KARMA<span style="color:rgba(255,255,255,0.3);">FORGES</span></span>
                    <button class="menu-toggle" onclick="toggleSidebar()">☰</button>
                </div>
                <div class="user">
                    <img class="avatar" id="userAvatar" src="" alt="Avatar" />
                    <span class="name" id="displayUsername">Loading...</span>
                    <button class="logout" onclick="logout()">Logout</button>
                </div>
                <a href="https://discord.com/oauth2/authorize?client_id=YOUR_CLIENT_ID&permissions=8&scope=bot" target="_blank" class="invite">+ Invite Bot</a>
            </div>

            <!-- Content -->
            <div id="view-overview" class="view-section active">
                <h2>Overview</h2>
                <div class="card">
                    <p style="color:var(--text3);font-size:14px;">Welcome back, <strong id="welcomeName" style="color:var(--text);">User</strong>.</p>
                    <div class="stats-grid" id="statsGrid">
                        <div class="stat"><div class="num" id="statScripts">0</div><div class="label">Scripts</div></div>
                        <div class="stat"><div class="num" id="statPanels">0</div><div class="label">Panels</div></div>
                        <div class="stat"><div class="num" id="statKeys">0</div><div class="label">Keys</div></div>
                        <div class="stat"><div class="num" id="statBanned">0</div><div class="label">Banned HWIDs</div></div>
                    </div>
                </div>
            </div>

            <!-- Scripts -->
            <div id="view-scripts" class="view-section">
                <h2>Scripts</h2>
                <div class="card">
                    <div class="flex">
                        <div class="grow">
                            <input type="text" id="scriptName" placeholder="Script name..." />
                        </div>
                        <label class="checkbox-container">
                            <input type="checkbox" id="ffaModeCheck" /> FFA
                        </label>
                        <label class="checkbox-container">
                            <input type="checkbox" id="compressModeCheck" /> Compress
                        </label>
                        <button class="btn btn-primary" onclick="createScript()">+ Create</button>
                    </div>
                    <textarea id="scriptCode" rows="6" placeholder="-- Paste your Lua code here..."></textarea>
                </div>
                <div id="scriptsList" class="scripts-grid"></div>
            </div>

            <!-- Panels -->
            <div id="view-panels" class="view-section">
                <h2>Panels</h2>
                <div class="card">
                    <input type="text" id="panelName" placeholder="Panel name..." />
                    <textarea id="panelDesc" rows="3" placeholder="Panel description..."></textarea>
                    <input type="text" id="panelChannel" placeholder="Discord Channel ID..." />
                    <select id="panelScript"><option value="">Select script...</option></select>
                    <input type="number" id="panelCooldown" placeholder="HWID cooldown (seconds)" value="180" />
                    <button class="btn btn-primary" onclick="createPanel()">+ Create Panel</button>
                </div>
                <div id="panelsList" class="scripts-grid"></div>
            </div>

            <!-- Keys -->
            <div id="view-keys" class="view-section">
                <h2>Keys</h2>
                <div class="card">
                    <select id="keyPanel"><option value="">Select panel...</option></select>
                    <input type="number" id="keyDuration" placeholder="Duration (hours, 0 = permanent)" value="0" />
                    <input type="text" id="keyNote" placeholder="Note (optional)" />
                    <div class="flex">
                        <button class="btn btn-primary" onclick="generateKey()">Generate Key</button>
                        <button class="btn btn-outline" onclick="addTimeAll()">+ Add Time to All</button>
                    </div>
                </div>
                <div id="keysList" class="scripts-grid"></div>
            </div>

            <!-- HWIDs -->
            <div id="view-hwids" class="view-section">
                <h2>HWID Bans</h2>
                <div class="card">
                    <div class="flex">
                        <div class="grow">
                            <input type="text" id="banHwidInput" placeholder="Enter HWID to ban..." />
                        </div>
                        <button class="btn btn-danger" onclick="banHwid()">Ban</button>
                    </div>
                </div>
                <div id="hwidsList" class="scripts-grid"></div>
            </div>

            <!-- Settings -->
            <div id="view-settings" class="view-section">
                <h2>Settings</h2>
                <div class="card">
                    <h4 style="margin-bottom:8px;font-weight:600;">Account</h4>
                    <p style="color:var(--text3);font-size:13px;margin-bottom:16px;">Manage your account settings.</p>
                    <button class="btn btn-danger" onclick="deleteAccount()">Delete Account</button>
                </div>
            </div>
        </main>
    </div>

    <script>
        // ===== DATA =====
        let currentData = { scripts: [], panels: [], keys: [], bannedHWIDs: [] };
        let serverTime = Date.now();

        // ===== AUTH =====
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
                document.getElementById('welcomeName').innerText = user;
                document.getElementById('userAvatar').src = (avatar && avatar !== 'null') ?
                    `https://cdn.discordapp.com/avatars/${id}/${avatar}.png` :
                    `https://cdn.discordapp.com/embed/avatars/0.png`;
                loadData();
            } else {
                document.getElementById('auth-wrapper').style.display = 'flex';
                document.getElementById('dashboard-content').style.display = 'none';
            }
        }

        function logout() {
            localStorage.clear();
            window.location.href = '/';
        }

        // ===== SIDEBAR =====
        function toggleSidebar() {
            document.getElementById('sidebar').classList.toggle('open');
            document.getElementById('sidebarOverlay').classList.toggle('open');
        }

        function closeSidebar() {
            document.getElementById('sidebar').classList.remove('open');
            document.getElementById('sidebarOverlay').classList.remove('open');
        }

        function switchView(view, el) {
            document.querySelectorAll('.view-section').forEach(v => v.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            document.getElementById('view-' + view).classList.add('active');
            if (el) el.classList.add('active');
            closeSidebar();
        }

        // ===== API =====
        function getHeaders() {
            return { 'Content-Type': 'application/json' };
        }

        async function loadData() {
            try {
                const res = await fetch('/api/data', { headers: getHeaders() });
                const data = await res.json();
                if (data.error) return;
                currentData = data;
                serverTime = data.serverTime || Date.now();
                renderAll();
            } catch (e) { console.error(e); }
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

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function renderScripts() {
            const container = document.getElementById('scriptsList');
            if (!currentData.scripts.length) {
                container.innerHTML =
                    '<div style="grid-column:1/-1;padding:30px;text-align:center;color:var(--text3);background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);">No scripts yet. Create one above.</div>';
                return;
            }
            let html = '';
            for (const s of currentData.scripts) {
                const statusBadge = s.status === 'active' ? 'badge-active' : 'badge-disabled';
                const statusText = s.status === 'active' ? 'Active' : 'Disabled';
                const ffaBadge = s.ffa_mode ? '<span class="badge badge-ffa">FFA</span>' : '';
                const date = new Date(s.created_at).toLocaleDateString();
                html += `<div class="script-card">
                    <div class="title">${escapeHtml(s.name)}</div>
                    <div class="meta"><span class="badge ${statusBadge}">${statusText}</span> ${ffaBadge} ${date}</div>
                    <div class="actions">
                        <button class="btn btn-outline btn-sm" onclick="toggleScript('${s.id}')">${s.status==='active'?'Disable':'Enable'}</button>
                        <button class="btn btn-outline btn-sm" onclick="toggleFfa('${s.id}')">${s.ffa_mode?'Disable FFA':'Enable FFA'}</button>
                        <button class="btn btn-danger btn-sm" onclick="deleteScript('${s.id}')">Delete</button>
                    </div>
                </div>`;
            }
            container.innerHTML = html;
        }

        function renderPanels() {
            const container = document.getElementById('panelsList');
            if (!currentData.panels.length) {
                container.innerHTML =
                    '<div style="grid-column:1/-1;padding:30px;text-align:center;color:var(--text3);background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);">No panels yet. Create one above.</div>';
                return;
            }
            let html = '';
            for (const p of currentData.panels) {
                html += `<div class="script-card">
                    <div class="title">${escapeHtml(p.name)}</div>
                    <div class="meta">${escapeHtml(p.description || 'No description')}</div>
                    <div class="actions">
                        <button class="btn btn-success btn-sm" onclick="sendPanel('${p.id}')">Send</button>
                        <button class="btn btn-danger btn-sm" onclick="deletePanel('${p.id}')">Delete</button>
                    </div>
                </div>`;
            }
            container.innerHTML = html;
        }

        function renderKeys() {
            const container = document.getElementById('keysList');
            if (!currentData.keys.length) {
                container.innerHTML =
                    '<div style="grid-column:1/-1;padding:30px;text-align:center;color:var(--text3);background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);">No keys generated yet.</div>';
                return;
            }
            let html = '';
            for (const k of currentData.keys) {
                const expired = k.expires_at && new Date(k.expires_at).getTime() < serverTime;
                let status = 'Active',
                    badge = 'badge-active';
                if (expired) { status = 'Expired';
                    badge = 'badge-disabled'; } else if (k.hwid) { status = 'HWID Locked';
                    badge = 'badge-ffa'; }
                html += `<div class="script-card">
                    <div class="title" style="font-family:monospace;font-size:12px;">${escapeHtml(k.key)}</div>
                    <div class="meta"><span class="badge ${badge}">${status}</span> ${k.note ? escapeHtml(k.note) : ''}</div>
                    <div class="actions"><button class="btn btn-danger btn-sm" onclick="deleteKey('${k.key}')">Delete</button></div>
                </div>`;
            }
            container.innerHTML = html;
        }

        function renderHwids() {
            const container = document.getElementById('hwidsList');
            if (!currentData.bannedHWIDs.length) {
                container.innerHTML =
                    '<div style="grid-column:1/-1;padding:30px;text-align:center;color:var(--text3);background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);">No banned HWIDs.</div>';
                return;
            }
            let html = '';
            for (const h of currentData.bannedHWIDs) {
                html += `<div class="script-card">
                    <div class="title" style="font-family:monospace;font-size:12px;color:rgba(255,255,255,0.5);">${escapeHtml(h.hwid)}</div>
                    <div class="meta">Banned ${new Date(h.created_at).toLocaleDateString()}</div>
                    <div class="actions"><button class="btn btn-outline btn-sm" onclick="unbanHwid('${h.hwid}')">Unban</button></div>
                </div>`;
            }
            container.innerHTML = html;
        }

        function updateSelects() {
            const panelScript = document.getElementById('panelScript');
            panelScript.innerHTML = '<option value="">Select script...</option>';
            for (const s of currentData.scripts) {
                panelScript.innerHTML += `<option value="${s.id}">${escapeHtml(s.name)}</option>`;
            }
            const keyPanel = document.getElementById('keyPanel');
            keyPanel.innerHTML = '<option value="">Select panel...</option>';
            for (const p of currentData.panels) {
                keyPanel.innerHTML += `<option value="${p.id}">${escapeHtml(p.name)}</option>`;
            }
        }

        // ===== ACTIONS =====
        async function createScript() {
            const name = document.getElementById('scriptName').value.trim();
            const code = document.getElementById('scriptCode').value;
            const compressMode = document.getElementById('compressModeCheck').checked;
            if (!name || !code) return alert('Please enter a name and code.');
            await fetch('/api/create-script', { method: 'POST', headers: getHeaders(), body: JSON.stringify({ name, code,
                    compressMode }) });
            document.getElementById('scriptName').value = '';
            document.getElementById('scriptCode').value = '';
            document.getElementById('ffaModeCheck').checked = false;
            document.getElementById('compressModeCheck').checked = false;
            loadData();
        }

        async function toggleScript(id) {
            await fetch('/api/scripts/' + id + '/toggle', { method: 'PUT', headers: getHeaders() });
            loadData();
        }

        async function toggleFfa(id) {
            await fetch('/api/scripts/' + id + '/ffa', { method: 'PUT', headers: getHeaders() });
            loadData();
        }

        async function deleteScript(id) {
            if (!confirm('Delete this script?')) return;
            await fetch('/api/delete-script', { method: 'POST', headers: getHeaders(), body: JSON.stringify({ id }) });
            loadData();
        }

        async function createPanel() {
            const name = document.getElementById('panelName').value.trim();
            const description = document.getElementById('panelDesc').value;
            const channelId = document.getElementById('panelChannel').value.trim();
            const scriptId = document.getElementById('panelScript').value;
            const hwidCooldown = parseInt(document.getElementById('panelCooldown').value) || 180;
            if (!name || !channelId || !scriptId) return alert('Please fill in all required fields.');
            await fetch('/api/create-panel', { method: 'POST', headers: getHeaders(), body: JSON.stringify({ name,
                    description, channelId, scriptId, hwidCooldown }) });
            document.getElementById('panelName').value = '';
            document.getElementById('panelDesc').value = '';
            document.getElementById('panelChannel').value = '';
            document.getElementById('panelCooldown').value = '180';
            loadData();
        }

        async function sendPanel(id) {
            await fetch('/api/send-panel', { method: 'POST', headers: getHeaders(), body: JSON.stringify({ panelId: id }) });
            alert('Panel sent to Discord!');
        }

        async function deletePanel(id) {
            if (!confirm('Delete this panel?')) return;
            await fetch('/api/delete-panel', { method: 'POST', headers: getHeaders(), body: JSON.stringify({ id }) });
            loadData();
        }

        async function generateKey() {
            const panelId = document.getElementById('keyPanel').value;
            const durationHours = parseInt(document.getElementById('keyDuration').value) || 0;
            const note = document.getElementById('keyNote').value.trim();
            if (!panelId) return alert('Please select a panel.');
            await fetch('/api/generate-key', { method: 'POST', headers: getHeaders(), body: JSON.stringify({ panelId,
                    durationHours, note }) });
            document.getElementById('keyNote').value = '';
            loadData();
        }

        async function deleteKey(key) {
            if (!confirm('Delete this key?')) return;
            await fetch('/api/delete-key', { method: 'POST', headers: getHeaders(), body: JSON.stringify({ key }) });
            loadData();
        }

        async function addTimeAll() {
            const hours = prompt('How many hours to add to all keys?');
            if (!hours || isNaN(hours)) return;
            await fetch('/api/add-time-all', { method: 'POST', headers: getHeaders(), body: JSON.stringify({ hours: parseInt(
                        hours) }) });
            loadData();
        }

        async function banHwid() {
            const hwid = document.getElementById('banHwidInput').value.trim();
            if (!hwid) return alert('Enter an HWID to ban.');
            await fetch('/api/ban-hwid', { method: 'POST', headers: getHeaders(), body: JSON.stringify({ hwid }) });
            document.getElementById('banHwidInput').value = '';
            loadData();
        }

        async function unbanHwid(hwid) {
            if (!confirm('Unban this HWID?')) return;
            await fetch('/api/unban-hwid', { method: 'POST', headers: getHeaders(), body: JSON.stringify({ hwid }) });
            loadData();
        }

        async function deleteAccount() {
            if (!confirm('Are you sure? This action is permanent.')) return;
            const confirmText = prompt('Type DELETE to confirm:');
            if (confirmText !== 'DELETE') return alert('Confirmation failed.');
            await fetch('/api/delete-account', { method: 'POST', headers: getHeaders(), body: JSON.stringify({ confirm: 'DELETE' }) });
            alert('Account deleted.');
            logout();
        }

        // ===== INIT =====
        checkLogin();
    </script>
</body>
</html>`;

console.log('⚫ KarmaForges Black & White loaded with full dashboard');
