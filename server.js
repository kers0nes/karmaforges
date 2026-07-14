// server.js – KarmaForges v7.0 (OAUTH FULLY FIXED)

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

// ============ SESSION MIDDLEWARE (FIXED) ============
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

// ============ DISCORD AUTH (COMPLETELY REWRITTEN) ============

// Store OAuth states in memory with expiration
const oauthStates = new Map();

app.get('/api/auth/discord', (req, res) => {
  const state = crypto.randomBytes(18).toString('hex');
  const expires = Date.now() + 5 * 60 * 1000; // 5 minutes
  
  oauthStates.set(state, { expires, redirect: req.query.redirect || '/' });
  
  // Clean up old states
  for (const [key, value] of oauthStates) {
    if (value.expires < Date.now()) {
      oauthStates.delete(key);
    }
  }
  
  const redirectUri = `${publicBaseUrl()}/api/auth/discord/callback`;
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'identify guilds',
    state: state
  });
  
  console.log(`🔐 OAuth initiated with state: ${state}`);
  res.redirect(`https://discord.com/oauth2/authorize?${params.toString()}`);
});

app.get('/api/auth/discord/callback', async (req, res) => {
  const { code, state } = req.query;
  
  console.log(`🔄 OAuth callback received. State: ${state}, Code: ${code ? 'present' : 'missing'}`);
  
  // Check if state exists
  if (!state) {
    console.error('❌ No state parameter received');
    return res.status(400).send('Invalid OAuth state: No state parameter. Please try again.');
  }
  
  // Check if state is valid
  if (!oauthStates.has(state)) {
    console.error(`❌ Invalid state: ${state}`);
    return res.status(400).send('Invalid OAuth state: State not found. Please try again.');
  }
  
  const stateData = oauthStates.get(state);
  if (stateData.expires < Date.now()) {
    console.error('❌ State expired');
    oauthStates.delete(state);
    return res.status(400).send('Invalid OAuth state: State expired. Please try again.');
  }
  
  // Remove state after use
  oauthStates.delete(state);
  
  if (!code) {
    console.error('❌ No code received');
    return res.status(400).send('No authorization code received');
  }
  
  try {
    const redirectUri = `${publicBaseUrl()}/api/auth/discord/callback`;
    
    console.log('🔄 Exchanging code for token...');
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
    if (!tokenResponse.ok) {
      console.error('❌ Token error:', tokenData);
      throw new Error('Failed to get token: ' + (tokenData.error || 'Unknown error'));
    }
    
    console.log('✅ Token obtained');
    
    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const user = await userResponse.json();
    
    console.log(`👤 User authenticated: ${user.username} (${user.id})`);
    
    let dbUser = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(user.id);
    if (!dbUser) {
      const id = makeId('user');
      const referralCode = generateReferralCode();
      db.prepare(
        `INSERT INTO users (id, discord_id, username, avatar, referral_code)
         VALUES (?, ?, ?, ?, ?)`
      ).run(id, user.id, user.username, user.avatar || '', referralCode);
      dbUser = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(user.id);
      console.log('✅ New user created');
    } else {
      db.prepare(
        'UPDATE users SET username = ?, avatar = ?, updated_at = CURRENT_TIMESTAMP WHERE discord_id = ?'
      ).run(user.username, user.avatar || '', user.id);
      console.log('✅ User updated');
    }
    
    // Set session
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
      if (err) {
        console.error('❌ Session save error:', err);
        return res.status(500).send('Failed to save session. Please try again.');
      }
      console.log('✅ Session saved');
      const redirectUrl = `${publicBaseUrl()}/dashboard#user=${encodeURIComponent(user.username)}&id=${user.id}&avatar=${user.avatar || ''}`;
      res.redirect(redirectUrl);
    });
  } catch (e) {
    console.error('❌ Auth error:', e);
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
        .setColor(BRAND_COLOR)
        .setTitle(`📦 ${panel.name}`)
        .setDescription(panel.description || 'Use the buttons below to manage your script.')
        .addFields(
          { name: '📜 Script', value: `\`${db.prepare('SELECT name FROM scripts WHERE id = ?').get(panel.script_id)?.name || 'Unknown'}\``, inline: true },
          { name: '🔑 Status', value: '🟢 Active', inline: true }
        )
        .setFooter({ text: 'KarmaForges Panel • Click a button below' })
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
    activities: [{ name: 'KarmaForges | /help', type: ActivityType.Watching }]
  }
});

client.once('ready', () => {
  console.log(`🤖 Discord bot online as ${client.user.tag}`);
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
        .setColor(BRAND_COLOR)
        .setTitle('🐱 KarmaForges – Commands')
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
        .setFooter({ text: 'KarmaForges v7.0' })
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
        .setColor(BRAND_COLOR)
        .setTitle('✅ Account Ready')
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
        .setColor(BRAND_COLOR)
        .setTitle(`📜 Your Scripts (${scripts.length})`)
        .setDescription(scripts.map((s, i) =>
          `${i + 1}. **${s.name}** \`${s.id}\` - ${s.status === 'active' ? '🟢 Active' : '🔴 Disabled'}`
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
        .setColor(BRAND_COLOR)
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
        .setColor(BRAND_COLOR)
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
        .setColor(BRAND_COLOR)
        .setTitle(`📦 ${title}`)
        .setDescription(description)
        .addFields(
          { name: '📜 Script', value: `\`${script.name}\``, inline: true },
          { name: '📌 Version', value: `\`${script.version || '1.0.0'}\``, inline: true },
          { name: '🔑 Status', value: script.status === 'active' ? '🟢 Active' : '🔴 Disabled', inline: true }
        )
        .setFooter({ text: 'KarmaForges Panel • Click a button below' })
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
        .setColor(BRAND_COLOR)
        .setTitle(`📜 ${script.name}`)
        .addFields(
          { name: 'Version', value: script.version || '1.0.0', inline: true },
          { name: 'Status', value: script.status === 'active' ? '🟢 Active' : '🔴 Disabled', inline: true },
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
        .setColor(BRAND_COLOR)
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
      console.log(`🚀 KarmaForges v7.0 running on port ${port}`);
      console.log(`🌐 Website: ${publicBaseUrl()}`);
    });
  } catch (e) {
    console.error('Startup failed:', e);
  }

  await client.login(DISCORD_TOKEN);
})();

// ============ EMBEDDED INDEX.HTML ============
const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KarmaForges</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        :root { --bg: #09090b; --primary: #6366f1; --text: #f8fafc; --muted: #9ca3af; --border: rgba(255,255,255,0.08); }
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family: system-ui, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .glass { background: rgba(18,18,20,0.65); backdrop-filter: blur(20px); border: 1px solid var(--border); border-radius: 24px; padding: 48px 40px; max-width: 420px; width: 100%; text-align: center; }
        h1 { font-size: 28px; font-weight: 800; margin-bottom: 8px; }
        h1 span { color: var(--primary); }
        .sub { color: var(--muted); font-size: 14px; margin-bottom: 28px; }
        .btn-discord { display: inline-flex; align-items: center; justify-content: center; gap: 12px; width: 100%; padding: 16px; background: #5865F2; color: white; border: none; border-radius: 12px; font-weight: 700; font-size: 16px; cursor: pointer; text-decoration: none; transition: all 0.3s; }
        .btn-discord:hover { background: #4752C4; transform: translateY(-2px); box-shadow: 0 8px 30px rgba(88,101,242,0.4); }
        .btn-discord svg { width: 24px; height: 24px; fill: white; }
    </style>
</head>
<body>
<div class="glass">
    <h1>Karma<span>Forges</span></h1>
    <p class="sub">Ultimate script protection & key system</p>
    <a href="/api/auth/discord" class="btn-discord">
        <svg viewBox="0 0 127.14 96.36"><path d="M107.7,8.07A105.15,105.15,0,0,0,81.47,0a72.06,72.06,0,0,0-3.36,6.83A97.68,97.68,0,0,0,49,6.83,72.37,72.37,0,0,0,45.64,0,105.89,105.89,0,0,0,19.39,8.09C2.79,32.65-1.71,56.6.54,80.21h0A105.73,105.73,0,0,0,32.71,96.36,77.7,77.7,0,0,0,39.6,85.25a68.42,68.42,0,0,1-10.85-5.18c.91-.66,1.8-1.34,2.66-2a75.57,75.57,0,0,0,64.32,0c.87.71,1.76,1.39,2.66,2a68.68,68.68,0,0,1-10.87,5.19,77,77,0,0,0,6.89,11.1A105.25,105.25,0,0,0,126.6,80.22h0C129.24,52.84,122.09,29.11,107.7,8.07ZM42.45,65.69C36.18,65.69,31,60,31,53s5-12.74,11.43-12.74S54,46,53.89,53,48.84,65.69,42.45,65.69Zm42.24,0C78.41,65.69,73.31,60,73.31,53s5-12.74,11.43-12.74S96.1,46,96,53,91.08,65.69,84.69,65.69Z"/></svg>
        Login with Discord
    </a>
</div>
<script>
    const hash = window.location.hash;
    if (hash.includes('user=')) {
        const params = new URLSearchParams(hash.replace('#', '?'));
        const user = params.get('user');
        const id = params.get('id');
        const avatar = params.get('avatar');
        if (user && id) {
            localStorage.setItem('kf_user', user);
            localStorage.setItem('kf_id', id);
            localStorage.setItem('kf_avatar', avatar || '');
            window.location.href = '/dashboard';
        }
    }
    const stored = localStorage.getItem('kf_user');
    if (stored) window.location.href = '/dashboard';
</script>
</body>
</html>`;

console.log('✅ KarmaForges v7.0 loaded with fixed OAuth');
