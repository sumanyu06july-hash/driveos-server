const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const crypto = require('crypto');
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;

// ── LOCAL RUNTIME SECRET STORAGE ──
const fs = require('fs');
const STORAGE_PATH = process.env.DRIVEOS_STORAGE_PATH || '.';
const RUNTIME_SECRET_FILE = require('path').resolve(STORAGE_PATH, 'runtime-secrets.json');

function ensureRuntimeSecrets() {
  let config = {};
  try {
    if (fs.existsSync(RUNTIME_SECRET_FILE)) {
      config = JSON.parse(fs.readFileSync(RUNTIME_SECRET_FILE, 'utf8')) || {};
    }
  } catch (err) {
    console.error('CONFIG parse failed, falling back to empty config.', err.message);
    config = {};
  }

  let dirty = false;

  if (!config.globalSecret) { config.globalSecret = crypto.randomBytes(32).toString('hex'); dirty = true; }
  if (!config.adminPin) { config.adminPin = '' + (100000 + crypto.randomInt(900000)); dirty = true; }
  if (!config.masterPin) { config.masterPin = ('' + (10000 + crypto.randomInt(999900))).padStart(6, '0'); dirty = true; }
  if (!config.adminApiToken) { config.adminApiToken = crypto.randomBytes(48).toString('hex'); dirty = true; }

  if (dirty) {
    fs.mkdirSync(STORAGE_PATH, { recursive: true });
    fs.writeFileSync(RUNTIME_SECRET_FILE, JSON.stringify(config, null, 2), { encoding: 'utf8', mode: 0o600 });
    console.log('CONFIG: New runtime secrets generated once. Keep the persistent storage safe.');
  }

  return config;
}

const runtimeSecrets = ensureRuntimeSecrets();
const GLOBAL_SECRET = process.env.RELAY_SECRET || runtimeSecrets?.globalSecret;
const ADMIN_PIN = process.env.ADMIN_PIN || runtimeSecrets.adminPin;
const MASTER_PIN = process.env.MASTER_PIN || runtimeSecrets.masterPin;
function safeStringEqual(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

// ── ADMIN AUTH STATE ──
let previousADMIN_TOKEN = null;
let rotationTimestamp = 0;
let adminTokenExpiresAt = 0;
const TOKEN_GRACE_PERIOD_MS = 60 * 1000; // 60s grace period

let ADMIN_API_TOKEN = process.env.ADMIN_API_TOKEN || runtimeSecrets.adminApiToken;

// ── PERSISTENCE SETUP ──
const adapter = new FileSync(path.resolve(STORAGE_PATH, 'db.json'))
const db = low(adapter);

// Initialize database defaults
db.defaults({
    devices: {},
    blacklist: [],
    fingerprintBlacklist: []
}).write();

// ── SPOTIFY WEB API CREDENTIALS ──
// Do not expose credentials to URLs or logs. Spotify is optional.
const SPOTIFY_CLIENT_ID = process.env.SPOTIFY_CLIENT_ID || null;
const SPOTIFY_CLIENT_SECRET = process.env.SPOTIFY_CLIENT_SECRET || null;
if (!SPOTIFY_CLIENT_ID || !SPOTIFY_CLIENT_SECRET) {
    console.warn('[SPOTIFY] Not configured; Spotify search is disabled.');
}

let spotifyToken = null;
let spotifyTokenExpiresAt = 0;

async function getSpotifyToken() {
    const now = Date.now();
    if (spotifyToken && now < spotifyTokenExpiresAt) return spotifyToken;

    try {
        const authHeader = Buffer.from(`${SPOTIFY_CLIENT_ID}:${SPOTIFY_CLIENT_SECRET}`).toString('base64');
        const res = await fetch('https://accounts.spotify.com/api/token', {
            method: 'POST',
            headers: {
                'Authorization': `Basic ${authHeader}`,
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: 'grant_type=client_credentials'
        });

        const data = await res.json();
        if (data.access_token) {
            spotifyToken = data.access_token;
            spotifyTokenExpiresAt = now + (data.expires_in - 60) * 1000;
            console.log('⚡ [SPOTIFY]: Application access token refreshed successfully.');
            return spotifyToken;
        } else {
            console.error('❌ [SPOTIFY TOKEN ERROR]:', data);
        }
    } catch (err) {
        console.error('❌ [SPOTIFY AUTH ERROR]:', err.message);
    }
    return null;
}

async function querySpotifyTracks(query) {
    if (!query || query.trim().length === 0) return [];
    const token = await getSpotifyToken();
    if (!token) return [];

    try {
        const res = await fetch(`https://api.spotify.com/v1/search?q=${encodeURIComponent(query)}&type=track&limit=10`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await res.json();
        if (!data.tracks || !data.tracks.items) return [];

        return data.tracks.items.map(t => ({
            title: t.name,
            artist: t.artists.map(a => a.name).join(', '),
            uri: t.uri,
            cover: t.album.images[0]?.url || ''
        }));
    } catch (err) {
        console.error('❌ [SPOTIFY SEARCH ERROR]:', err.message);
        return [];
    }
}

// ── UTILITY FUNCTIONS FOR SECURE PURGE ──
function validateSpotifyUri(value) {
  if (typeof value !== 'string') return null;
  const uri = value.trim();

  if (/^spotify:(track|album|artist|playlist|episode|show):[A-Za-z0-9]+$/i.test(uri)) {
    return uri;
  }

  try {
    const url = new URL(uri);
    if (
      url.protocol !== 'https:' ||
      !['open.spotify.com', 'www.open.spotify.com'].includes(url.hostname)
    ) return null;

    const parts = url.pathname.split('/').filter(Boolean);
    if (parts.length < 2) return null;
    const type = parts[0];
    const id = parts[1];

    if (!/^(track|album|artist|playlist|episode|show)$/i.test(type)) return null;
    if (!/^[A-Za-z0-9]+$/.test(id)) return null;

    return `spotify:${type}:${id}`;
  } catch {
    return null;
  }
}

function generateCodeA() {
    return Math.floor(100000 + Math.random() * 900000).toString(); // 6 digits
}

function generateCodeB() {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';
    for (let i = 0; i < 16; i++) {
        result += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    return result;
}

function generateRecoveryCode() {
     return Math.floor(100000000000 + Math.random() * 900000000000).toString(); // 12 digits
}

// ── CENTRAL VOLATILE IN-MEMORY REGISTERS ──
const devices = new Map();
const adminClients = new Set();
const blacklist = new Set();
const fingerprintBlacklist = new Set();
let globalLogSequence = 1;

function persistSecurityFlag(deviceId, flag, value) {
    const dev = devices.get(deviceId);
    if (!dev) return;

    // Update in-memory first
    dev[flag] = value;

    // Atomic write to lowdb
    const currentDevices = db.get('devices').value() || {};
    if (Object.prototype.hasOwnProperty.call(currentDevices, deviceId) && typeof currentDevices[deviceId] !== 'object') {
        return;
    }
    if (!currentDevices[deviceId]) {
        currentDevices[deviceId] = {};
    }
    currentDevices[deviceId][flag] = value;

    db.set('devices', currentDevices).write();
    console.log(`🔒 [ATOMIC PERSISTENCE]: Device ${deviceId} flag ${flag} set to ${value}`);
}

function saveState() {
    const persistedDevices = {};
    for (const [id, dev] of devices.entries()) {
        // Convert Map/Set to plain objects/arrays for JSON serialization
        const serializedGuestTokens = {};
        if (dev.guestTokens) {
            for (const [token, meta] of dev.guestTokens.entries()) {
                serializedGuestTokens[token] = meta;
            }
        }

        persistedDevices[id] = {
            hud_banned: dev.hud_banned,
            companion_banned: dev.companion_banned,
            permanently_banned: dev.permanently_banned,
            lockout_active: dev.lockout_active,
            recovery_code: dev.recovery_code,
            parkedGuardActive: dev.parkedGuardActive,
            parkedCoords: dev.parkedCoords,
            parkedGuardState: dev.parkedGuardState,
            parkedGuardStateVersion: dev.parkedGuardStateVersion,
            parkedGuardArmedAt: dev.parkedGuardArmedAt,
            parkedGuardLastAckAt: dev.parkedGuardLastAckAt,
            parkedGuardAnchor: dev.parkedGuardAnchor,
            parkedGuardTelemetry: dev.parkedGuardTelemetry,
            parkedGuardAuditTrail: dev.parkedGuardAuditTrail,
            parkedGuardAlertCount: dev.parkedGuardAlertCount,
            parkedGuardLastAlertAt: dev.parkedGuardLastAlertAt,
            parkedGuardLastResult: dev.parkedGuardLastResult,
            parkedGuardPairingSecret: dev.parkedGuardPairingSecret,
            parkedGuardDisarmedAt: dev.parkedGuardDisarmedAt,
            parkedGuardLastSirenAt: dev.parkedGuardLastSirenAt,
            parkedGuardEscalationLevel: dev.parkedGuardEscalationLevel,
            parkedGuardPairingCreatedAt: dev.parkedGuardPairingCreatedAt,
            parkedGuardSigningEnabled: dev.parkedGuardSigningEnabled,
            guestPermissions: dev.guestPermissions,
            guestTokens: serializedGuestTokens,
            pendingWipe: dev.pendingWipe
        };
    }

    db.set('devices', persistedDevices)
      .set('blacklist', Array.from(blacklist))
      .set('fingerprintBlacklist', Array.from(fingerprintBlacklist))
      .write();

    console.log('💾 [PERSISTENCE]: System state synchronized to disk.');
    broadcastPersistenceStatus();
}

function broadcastPersistenceStatus() {
    const packet = JSON.stringify({ type: 'persistence_status', status: 'synced' });
    adminClients.forEach(admin => {
        if (admin.readyState === WebSocket.OPEN) admin.send(packet);
    });
}

function loadState() {
    const data = db.value();

    // Load blacklist
    if (data.blacklist) {
        data.blacklist.forEach(id => blacklist.add(id));
    }

    // Load fingerprint blacklist
    if (data.fingerprintBlacklist) {
        data.fingerprintBlacklist.forEach(fp => fingerprintBlacklist.add(fp));
    }

    // Load devices
    if (data.devices) {
        for (const [id, state] of Object.entries(data.devices)) {
            const dev = {
                headunit: null,
                companion: null,
                guests: new Set(),
                guestMetadata: new Map(),
                guestPermissions: state.guestPermissions || { allowPlayback: true, allowSuggestions: true },
                summaryClients: new Map(),
                summaryTokens: new Map(),
                guestTokens: new Map(),
                hudState: null,
                hudLastSeen: null,
                companionState: null,
                currentTrack: null,
                hud_banned: state.hud_banned || false,
                companion_banned: state.companion_banned || false,
                parkedGuardActive: state.parkedGuardActive || false,
                parkedCoords: state.parkedCoords || null,
                parkedGuardState: state.parkedGuardState || (state.parkedGuardActive ? 'ARMED' : 'DISARMED'),
                parkedGuardStateVersion: state.parkedGuardStateVersion || 0,
                parkedGuardArmedAt: state.parkedGuardArmedAt || null,
                parkedGuardLastAckAt: state.parkedGuardLastAckAt || null,
                parkedGuardAnchor: state.parkedGuardAnchor || null,
                parkedGuardTelemetry: state.parkedGuardTelemetry || null,
                parkedGuardAuditTrail: Array.isArray(state.parkedGuardAuditTrail) ? state.parkedGuardAuditTrail.slice(0, 100) : [],
                parkedGuardAlertCount: state.parkedGuardAlertCount || 0,
                parkedGuardLastResult: state.parkedGuardLastResult || null,
                parkedGuardLastAlertAt: state.parkedGuardLastAlertAt || null,
                parkedGuardPairingSecret: state.parkedGuardPairingSecret || null,
                parkedGuardDisarmedAt: state.parkedGuardDisarmedAt || null,
                parkedGuardLastSirenAt: state.parkedGuardLastSirenAt || null,
                parkedGuardEscalationLevel: state.parkedGuardEscalationLevel || 0,
                parkedGuardPairingCreatedAt: state.parkedGuardPairingCreatedAt || null,
                parkedGuardSigningEnabled: (state.parkedGuardPairingSecret || null) ? true : false,
                pendingWipe: state.pendingWipe || {
                    active: false,
                    codeA: null,
                    codeB: null,
                    approved: false,
                    huBackupReceived: false,
                    compBackupReceived: false
                },
                lockout_active: state.lockout_active || false,
                recovery_code: state.recovery_code || null,
                permanently_banned: state.permanently_banned || false
            };

            if (state.guestTokens) {
                for (const [token, meta] of Object.entries(state.guestTokens)) {
                    dev.guestTokens.set(token, meta);
                }
            }

            devices.set(id, dev);
        }
    }
    console.log(`🛡️ [PERSISTENCE]: Loaded ${devices.size} devices, ${blacklist.size} blacklist entries, and ${fingerprintBlacklist.size} fingerprints.`);
}

// Initial load
loadState();

console.log('====================================================');
console.log('🛡️  [DRIVEOS HYBRID CORE]: Initializing Secured State');
console.log(`📦  Blacklisted Clusters:       ${blacklist.size}`);
console.log(`🔒  Quarantined Fingerprints:   ${fingerprintBlacklist.size}`);
console.log('====================================================');

function isValidDeviceId(id) {
  const blocked = new Set(['__proto__', 'constructor', 'prototype', 'toString', 'valueOf']);
  return typeof id === 'string'
      && /^[A-Za-z0-9_-]{3,64}$/.test(id)
      && !blocked.has(id);
}
function getDevice(id) {
    if (!isValidDeviceId(id)) return null;
    if (!devices.has(id)) {
        devices.set(id, {
            headunit: null,
            companion: null,
            paired: false,
            relayCredential: null,
            pairCodeHash: null,
            pairCodeExpiresAt: null,
            linkedHeadunit: null,
            linkedCompanion: null,
            linkCodeHash: null,
            linkCodeExpiresAt: null,
            linkCodeUsed: false,
            guests: new Set(),
            guestMetadata: new Map(),
            guestPermissions: { allowPlayback: true, allowSuggestions: true },
            summaryClients: new Map(),
            summaryTokens: new Map(),
            guestTokens: new Map(), // token -> { type, burned, expiresAt, createdBy }
            hudState: null,
            hudLastSeen: null,
            companionState: null,
            currentTrack: null,
            hud_banned: false,
            companion_banned: false,
            parkedGuardActive: false,
            parkedCoords: null,
            parkedGuardState: 'DISARMED',
            parkedGuardStateVersion: 0,
            parkedGuardArmedAt: null,
            parkedGuardLastAckAt: null,
            parkedGuardAnchor: null,
            parkedGuardTelemetry: null,
            parkedGuardAuditTrail: [],
            parkedGuardAlertCount: 0,
            parkedGuardLastResult: null,
            parkedGuardLastAlertAt: null,
            parkedGuardPairingSecret: null,
            parkedGuardDisarmedAt: null,
            parkedGuardLastSirenAt: null,
            parkedGuardEscalationLevel: 0,
            parkedGuardPairingCreatedAt: null,
            parkedGuardSigningEnabled: false,
            // ── SECURE PURGE STATE ──
            pendingWipe: {
                active: false,
                codeA: null,
                codeB: null,
                approved: false,
                huBackupReceived: false,
                compBackupReceived: false
            },
            // ── LOCKOUT & BANNING STATE ──
            lockout_active: false,
            recovery_code: null,
            permanently_banned: false
        });
        saveState(); // Persist new device creation
    }
    return devices.get(id);
}

function sendToHeadunits(deviceId, type, payload = {}) {
    const device = getDevice(deviceId);
    if (!device || !device.headunit || device.headunit.readyState !== WebSocket.OPEN) {
        return 0;
    }
    try {
        device.headunit.send(JSON.stringify(Object.assign({}, payload, { type })));
        return 1;
    } catch (err) {
        console.error('[SEND_TO_HEADUNITS] failed:', err);
        return 0;
    }
}

const protectedNames = new Set([
  '.env', '.secret', 'db.json', 'package.json', 'package-lock.json',
  'server.js', 'server_stress.log', 'runtime-secrets.json'
]);

app.use((req, res, next) => {
  const pathname = decodeURIComponent(req.path || '');
  const basename = path.basename(pathname).toLowerCase();
  if (pathname.includes('/node_modules/')
      || pathname.startsWith('/node_modules')
      || basename.startsWith('.')
      || protectedNames.has(basename)
      || pathname.toLowerCase().endsWith('.map')
      || pathname.toLowerCase().endsWith('.mjs')
      || pathname.toLowerCase().endsWith('.cjs')) {
    return res.status(403).send('Protected application path.');
  }
  next();
});
app.use(express.static(path.join(__dirname), {
  dotfiles: 'deny',
  index: false,
  redirect: false
}));
app.use(express.json());


// ── ACCESS DENIED HTML TEMPLATE ──
const ACCESS_DENIED_HTML = `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>DriveOS · Access Denied</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700;800&display=swap" rel="stylesheet"/>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: #080000;
    color: #ff2244;
    font-family: 'JetBrains Mono', monospace;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    padding: 24px;
    text-align: center;
  }
  .box {
    border: 1px solid rgba(255,34,68,0.3);
    background: rgba(255,34,68,0.04);
    border-radius: 12px;
    padding: 32px 24px;
    max-width: 360px;
    width: 100%;
    box-shadow: 0 0 30px rgba(255,34,68,0.2);
  }
  h1 { font-size: 16px; font-weight: 800; letter-spacing: 0.2em; margin-bottom: 12px; text-shadow: 0 0 10px rgba(255,34,68,0.5); }
  p { font-size: 10px; letter-spacing: 0.1em; color: rgba(255,34,68,0.8); line-height: 1.6; text-transform: uppercase; }
</style>
</head>
<body>
  <div class="box">
    <h1>[SECURITY]: ACCESS DENIED</h1>
    <p>Invalid, expired, or already burned access token. Vehicle nexus connection refused.</p>
  </div>
</body>
</html>
`;

// ── SECURE ROUTE MIDDLEWARE: STRICT TOKEN GATING & LOGGING ──

app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

app.get('/guest', (req, res) => {
    const deviceId = req.query.device || 'myaura001';
    const token = req.query.token;
    const dev = devices.get(deviceId);

    if (!token || !dev || !dev.guestTokens.has(token)) {
        return res.status(403).send(ACCESS_DENIED_HTML);
    }

    const tokenMeta = dev.guestTokens.get(token);
    if (tokenMeta.burned) {
        return res.status(403).send(ACCESS_DENIED_HTML);
    }

    res.sendFile(path.join(__dirname, 'guest.html'));
});

app.get('/summary', (req, res) => {
    const deviceId = req.query.device || 'myaura001';
    const token = req.query.token;
    const dev = devices.get(deviceId);

    if (!token || !dev || !dev.guestTokens.has(token)) {
        return res.status(403).send(ACCESS_DENIED_HTML);
    }

    const tokenMeta = dev.guestTokens.get(token);
    if (tokenMeta.burned) {
        return res.status(403).send(ACCESS_DENIED_HTML);
    }

    res.sendFile(path.join(__dirname, 'summary.html'));
});

app.post('/admin/rotate-token', requireAdmin, (req, res) => {
  const newToken = require('crypto').randomBytes(32).toString('hex');

  previousADMIN_TOKEN = ADMIN_API_TOKEN;
  ADMIN_API_TOKEN = newToken;
  rotationTimestamp = Date.now();

  console.log('🔑 [AUTH]: Admin token rotated (new token value redacted).');

  // Broadcast rotation event (WITHOUT newToken) to admin clients
  const packet = JSON.stringify({ type: 'admin_token_rotated' });
  adminClients.forEach(admin => {
    if (admin.readyState === WebSocket.OPEN) admin.send(packet);
  });

  res.json({ ok: true, newToken });
});

function requireAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ ok: false, error: 'Missing Authorization header' });

  const token = authHeader.replace('Bearer ', '').trim();

  // Check current token
  if (token === ADMIN_API_TOKEN) {
    return next();
  }

  // Check previous token within grace period
  if (previousADMIN_TOKEN && token === previousADMIN_TOKEN) {
    const now = Date.now();
    if (now - rotationTimestamp < TOKEN_GRACE_PERIOD_MS) {
      return next();
    }
  }

  res.status(403).json({ ok: false, error: 'Invalid Admin Token' });
}
// ── 48-DIGIT DEVICE PAIRING (opt-in; does not affect existing legacy connections unless enabled) ──
app.post('/admin/pair-code', requireAdmin, (req, res) => {
    const deviceId = req.body.device;
    if (!isValidDeviceId(deviceId)) return res.status(400).json({ ok: false, error: 'Invalid device id.' });

    const code = Array.from({ length: 48 }, () => Math.floor(Math.random() * 10)).join('');
    const dev = getDevice(deviceId);
    if (!dev) return res.status(404).json({ ok: false, error: 'Device not found.' });

    dev.pairCodeHash = crypto.createHash('sha256').update(code).digest('hex');
    dev.pairCodeExpiresAt = Date.now() + 10 * 60 * 1000;
    dev.paired = false;
    saveState();

    // The code is shown only once to the admin for handoff to the physical device.
    res.json({ ok: true, deviceId, pairCode: code, expiresAt: dev.pairCodeExpiresAt });
});

app.post('/api/pair', (req, res) => {
    const deviceId = req.body.device;
    const pairCode = String(req.body.pairCode || '').trim();

    if (!isValidDeviceId(deviceId) || !/^\d{48}$/.test(pairCode)) {
        return res.status(400).json({ ok: false, error: 'Invalid device or pair code.' });
    }

    const dev = getDevice(deviceId);
    if (!dev || !dev.pairCodeHash || !dev.pairCodeExpiresAt || Date.now() > dev.pairCodeExpiresAt) {
        return res.status(403).json({ ok: false, error: 'No valid pairing in progress.' });
    }

    const suppliedHash = crypto.createHash('sha256').update(pairCode).digest('hex');
    if (suppliedHash !== dev.pairCodeHash) {
        return res.status(403).json({ ok: false, error: 'Invalid pair code.' });
    }

    const credential = crypto.randomBytes(32).toString('hex');
    dev.relayCredential = credential;
    dev.paired = true;
    dev.pairCodeHash = null;
    dev.pairCodeExpiresAt = null;
    saveState();

    res.json({ ok: true, deviceId, relayCredential: credential });
});

app.post('/api/link-code', (req, res) => {
    const deviceId = req.body.device;
    const credential = String(req.body.credential || '').trim();

    if (!isValidDeviceId(deviceId)) return res.status(400).json({ ok: false, error: 'Invalid device id.' });

    const dev = getDevice(deviceId);
    if (!dev || !dev.paired || !dev.relayCredential || credential !== dev.relayCredential) {
        return res.status(403).json({ ok: false, error: 'Unpaired or unauthorized device.' });
    }

    const code = Array.from({ length: 48 }, () => Math.floor(Math.random() * 10)).join('');
    dev.linkCodeHash = crypto.createHash('sha256').update(code).digest('hex');
    dev.linkCodeExpiresAt = Date.now() + 8 * 60 * 1000;
    dev.linkCodeUsed = false;
    saveState();
    res.json({ ok: true, deviceId, linkCode: code, expiresAt: dev.linkCodeExpiresAt });
});

app.post('/api/link', (req, res) => {
    const companionDevice = req.body.companionDevice;
    const companionCredential = String(req.body.companionCredential || '').trim();
    const headunitLinkCode = String(req.body.linkCode || '').trim();

    if (!isValidDeviceId(companionDevice) || !/^\d{48}$/.test(headunitLinkCode)) {
        return res.status(400).json({ ok: false, error: 'Invalid companion device or link code.' });
    }

    const companionDev = getDevice(companionDevice);
    if (!companionDev || !companionDev.paired || !companionDev.relayCredential || companionCredential !== companionDev.relayCredential) {
        return res.status(403).json({ ok: false, error: 'Unpaired or unauthorized companion.' });
    }

    // Find the headunit associated with this code without trusting freeform input.
    let headunitDev = null;
    for (const [id, dev] of devices.entries()) {
        if (dev.linkCodeHash) {
            const suppliedHash = crypto.createHash('sha256').update(headunitLinkCode).digest('hex');
            if (suppliedHash === dev.linkCodeHash && !dev.linkCodeUsed && Date.now() <= dev.linkCodeExpiresAt) {
                headunitDev = dev;
                // consume immediately
                dev.linkCodeUsed = true;
                dev.linkCodeHash = null;
                dev.linkCodeExpiresAt = null;
                break;
            }
        }
    }

    if (!headunitDev) {
        return res.status(403).json({ ok: false, error: 'Invalid, expired, or already used link code.' });
    }

    headunitDev.linkedCompanion = companionDevice;
    companionDev.linkedHeadunit = [...devices.entries()].find(([id, d]) => d === headunitDev)?.[0] || null;
    saveState();

    res.json({ ok: true, linkedHeadunit: companionDev.linkedHeadunit, linkedCompanion: headunitDev.linkedCompanion });
});

// ---------- Unpair endpoint ----------
// Revokes a device's relay credential and clears any companion link.
app.post('/api/unpair', (req, res) => {
    const deviceId = String(req.body.device || '').trim();
    const credential = String(req.body.credential || '').trim();

    if (!isValidDeviceId(deviceId)) {
        return res.status(400).json({ ok: false, error: 'invalid' });
    }

    if (!devices.has(deviceId)) {
        return res.status(403).json({ ok: false, error: 'unpaired' });
    }

    const dev = devices.get(deviceId);
    if (!dev || !dev.paired || !dev.relayCredential || credential !== dev.relayCredential) {
        return res.status(403).json({ ok: false, error: 'unpaired' });
    }

    // Clear reverse links on the counterpart(s).
    if (dev.linkedCompanion && devices.has(dev.linkedCompanion)) {
        const companion = devices.get(dev.linkedCompanion);
        if (companion) companion.linkedHeadunit = null;
    }
    if (dev.linkedHeadunit && devices.has(dev.linkedHeadunit)) {
        const headunit = devices.get(dev.linkedHeadunit);
        if (headunit) headunit.linkedCompanion = null;
    }

    dev.paired = false;
    dev.relayCredential = null;
    dev.linkedHeadunit = null;
    dev.linkedCompanion = null;
    dev.linkCodeHash = null;
    dev.linkCodeExpiresAt = null;
    dev.linkCodeUsed = false;
    saveState();

    res.json({ ok: true, device: deviceId, serverTime: Date.now() });
});

app.post('/admin/play-spotify', requireAdmin, (req, res) => {
  const deviceId = req.body.device;
  const uri = validateSpotifyUri(req.body.uri);

  if (!deviceId || !uri) {
    return res.status(400).json({ ok: false, error: 'Invalid deviceId or Spotify URI.' });
  }

  const delivered = sendToHeadunits(deviceId, 'cmd_spotify_play', {
    uri,
    track: { uri },
    source: 'admin_direct_control',
    requestedAt: new Date().toISOString()
  });

  if (delivered === 0) {
    return res.status(503).json({ ok: false, error: 'No connected nodes for this device.', delivered: 0 });
  }

  res.json({ ok: true, message: 'Command sent to Headunit.', uri, delivered });
});

app.post('/admin/set-destination', requireAdmin, (req, res) => {
  const deviceId = req.body.device;
  const destination = req.body.destination;

  if (!deviceId || !destination) {
    return res.status(400).json({ ok: false, error: 'deviceId and destination are required.' });
  }

  const { lat, lng } = destination;
  if (lat === undefined || lng === undefined) {
    return res.status(400).json({ ok: false, error: 'Destination must contain lat and lng.' });
  }

  console.log(`📍 [DESTINATION]: Request for ${deviceId} to ${lat}, ${lng}`);

  const delivered = sendToHeadunits(deviceId, 'cmd_set_destination', {
    destination,
    requestedAt: new Date().toISOString(),
    source: 'admin_direct_control'
  });

  if (delivered === 0) {
    return res.status(503).json({ ok: false, error: 'No connected nodes for this device.', delivered: 0 });
  }

  res.json({ ok: true, message: 'Destination set successfully.', destination, delivered });
});

app.post('/admin/pause', requireAdmin, (req, res) => {
  const deviceId = req.body.device;
  if (!deviceId) return res.status(400).json({ ok: false, error: 'deviceId is required.' });

  const delivered = sendToHeadunits(deviceId, 'cmd_music', {
    action: 'pause',
    source: 'admin_direct_control',
    requestedAt: new Date().toISOString()
  });

  if (delivered === 0) {
    return res.status(503).json({ ok: false, error: 'No connected nodes for this device.', delivered: 0 });
  }

  res.json({ ok: true, message: 'Pause command sent.', delivered });
});

app.get('/api/unban-all', requireAdmin, (req, res) => {
    console.warn(`🚨 [SECURITY]: Admin ${req.ip || 'unknown'} requested global unban-all.`);

    blacklist.clear();
    fingerprintBlacklist.clear();
    for (const [, dev] of devices.entries()) {
        dev.hud_banned = false;
        dev.companion_banned = false;
        dev.permanently_banned = false; // Added
        dev.lockout_active = false; // Added
    }
    saveState();
    broadcastTopology();
    res.send('<h1 style="font-family:sans-serif;color:#00c853;">✅ SUCCESS: All device bans, node lockdowns, and fingerprint quarantines cleared from memory!</h1>');
});

function reject(ws, type, message) {
    console.warn(`[REJECT] ${type} — ${message}`);
    try {
        ws.send(JSON.stringify({ type: 'error', message }));
        ws.close();
    } catch (e) {}
}

function broadcastTopology() {
    try {
        const data = [];
        let absoluteLatencySum = 0;
        let computedCount = 0;

        for (const [deviceId, dev] of devices.entries()) {
            const huActive = !!dev.headunit && dev.headunit.readyState === WebSocket.OPEN;
            const compActive = !!dev.companion && dev.companion.readyState === WebSocket.OPEN;

            let hudLatency = dev.hudState?.latency ? parseInt(dev.hudState.latency) || 0 : (huActive ? 35 + Math.floor(Math.random() * 10) : 0);
            let compLatency = dev.companionState?.latency ? parseInt(dev.companionState.latency) || 0 : (compActive ? 40 + Math.floor(Math.random() * 12) : 0);

            if (huActive) { absoluteLatencySum += hudLatency; computedCount++; }
            if (compActive) { absoluteLatencySum += compLatency; computedCount++; }

            const tokenList = [];
            if (dev.guestTokens) {
                for (const [, meta] of dev.guestTokens.entries()) {
                    tokenList.push({
                        type: meta.type || 'guest',
                        burned: meta.burned === true
                    });
                }
            }

            // Security: do not expose any connected guest metadata beyond a count.
            const activeGuestsCount = dev.guestMetadata ? dev.guestMetadata.size : 0;

            data.push({
                id: deviceId,
                isBlacklisted: blacklist.has(deviceId),
                permanently_banned: dev.permanently_banned,
                lockout_active: dev.lockout_active,
                hud_banned: dev.hud_banned,
                companion_banned: dev.companion_banned,
                parkedGuardActive: dev.parkedGuardActive,
                activeGuests: activeGuestsCount,
                guestPermissions: dev.guestPermissions,
                activeSummaryTokens: tokenList,
                hud: {
                    connected: huActive,
                    latency: hudLatency,
                    lastSeen: dev.hudLastSeen,
                    state: {
                        // Do not forward device telemetry details unredacted to all admins.
                        speed: dev.hudState ? dev.hudState.speed : 0,
                        fuel_percent: dev.hudState ? dev.hudState.fuel_percent : 100,
                        odometer: dev.hudState ? dev.hudState.odometer : 0,
                        battery_voltage: dev.hudState ? dev.hudState.battery_voltage : 12.6
                    }
                },
                companion: {
                    connected: compActive,
                    latency: compLatency,
                    state: {
                        battery: dev.companionState ? dev.companionState.battery : 100,
                        signal: dev.companionState ? dev.companionState.signal || 'Good' : 'Excellent'
                    }
                }
            });
        }

        const avgLatency = computedCount ? Math.round(absoluteLatencySum / computedCount) : 0;
        const packet = JSON.stringify({
            type: 'topology_update',
            data,
            metrics: { avgLatency },
            bannedFingerprintsCount: fingerprintBlacklist.size
        });

        adminClients.forEach(admin => {
            if (admin.readyState === WebSocket.OPEN) admin.send(packet);
        });
    } catch (err) {
        console.error('[TOPO ERROR]:', err.message);
    }
}

function interceptTelemetryTransaction(origin, target, payload) {
    // Security: do not forward unfiltered payload content to the admin wiretap views.
    const safePayload = { event: typeof payload?.type === 'string' ? payload.type : 'unknown', origin: 'server-redacted' };
    const packet = JSON.stringify({
        type: 'wiretap_intercept',
        sequence: String(globalLogSequence++).padStart(4, '0'),
        origin, target, payload: safePayload
    });
    adminClients.forEach(admin => { if (admin.readyState === WebSocket.OPEN) admin.send(packet); });
}

// Registered companion-to-headunit directives. Hoisted to module scope so
// the WebSocket frame hot path never allocates this Set per message.
const COMPANION_TO_HEADUNIT_TYPES = new Set([
    'backup_data',
    'cmd_bind',
    'cmd_bind_device',
    'cmd_diagnostic',
    'cmd_display',
    'cmd_export_data',
    'cmd_export_fuel_only',
    'cmd_failover',
    'cmd_fuel_entry',
    'cmd_fuel_push',
    'cmd_generate_test_data',
    'cmd_generate_web_summary',
    'cmd_get_last_odo',
    'cmd_mode',
    'cmd_music',
    'cmd_open',
    'cmd_open_module',
    'cmd_panic',
    'cmd_set_destination',
    'cmd_spotify_play',
    'cmd_theme',
    'cmd_theme_sync',
    'cmd_trigger_failover',
    'cmd_trip',
    'cmd_vol',
    'cmd_volume'
]);

// ── PARKED GUARD S7-S10 SECURITY CONTRACT ──
const PARKED_GUARD_SIGNATURE_WINDOW_MS = 90 * 1000;
const PARKED_GUARD_NONCE_CACHE_TTL_MS = 5 * 60 * 1000;
const PARKED_GUARD_AUDIT_LIMIT = 250;
const PARKED_GUARD_ALERT_CLEAR_MS = 60 * 1000 * 10;
const PARKED_GUARD_SIREN_ESCALATION_LEVELS = Object.freeze(['companion_passthrough', 'movement_alert', 'escalating_auto_siren']);

function enqueueParkedGuardAudit(dev, entry) {
    if (!dev) return;
    const safeEntry = Object.assign({
        at: Date.now(),
        result: 'unknown',
        detail: '',
        request_id: null,
        action: 'unknown',
        actor: 'unknown',
        state_version: dev.parkedGuardStateVersion || 0
    }, entry || {});
    dev.parkedGuardAuditTrail = (dev.parkedGuardAuditTrail || []).concat([safeEntry]).slice(-PARKED_GUARD_AUDIT_LIMIT);
    try { dev.parkedGuardLastResult = Object.assign({}, safeEntry); } catch (e) {}
}

function parkedGuardPairSecret(dev) {
    if (dev.parkedGuardPairingSecret) return dev.parkedGuardPairingSecret;
    if (!crypto) return null;
    const generated = crypto.randomBytes(32).toString('base64url');
    dev.parkedGuardPairingSecret = generated;
    dev.parkedGuardPairingCreatedAt = Date.now();
    dev.parkedGuardSigningEnabled = true;
    return generated;
}

function hasParkedGuardSigningSupport() {
    try { return typeof crypto.createHmac === 'function'; }
    catch (e) { return false; }
}

function validateParkedGuardSignature(dev, msg) {
    const pairingSecret = dev.parkedGuardPairingSecret;
    if (!pairingSecret || !hasParkedGuardSigningSupport()) return { ok: false, error: 'Pairing key unavailable.' };

    const action = (msg.action == null) ? '' : String(msg.action);
    const commandType = String(msg.type || '');
    const requestId = String(msg.request_id || '');
    const commandTimestamp = Number(msg.timestamp);
    const nonce = (msg.nonce == null) ? '' : String(msg.nonce);
    const stateVersionTarget = Number.isFinite(msg.state_version_expected)
        ? Number(msg.state_version_expected)
        : (dev.parkedGuardStateVersion || 0);
    const signatureBase64 = (msg.signature == null) ? '' : String(msg.signature);

    if (!requestId || requestId.length > 128) return { ok: false, error: 'request_id is required.' };
    if (!nonce || nonce.length > 128) return { ok: false, error: 'nonce is required.' };
    if (!Number.isFinite(commandTimestamp)) return { ok: false, error: 'timestamp is required.' };
    const now = Date.now();
    if (Math.abs(now - commandTimestamp) > PARKED_GUARD_SIGNATURE_WINDOW_MS) return { ok: false, error: 'command timestamp outside replay window.' };
    if (!action) return { ok: false, error: 'signed action is required.' };

    // Enforce nonce uniqueness / basic replay protection across any currently tracked key.
    if (!Array.isArray(dev.parkedGuardNonceJournal)) dev.parkedGuardNonceJournal = [];
    const nonceDigest = crypto.createHash('sha256').update(`${nonce}:${dev.parkedGuardPairingCreatedAt || 0}`).digest('hex');
    const expiredNonceWindowStart = now - PARKED_GUARD_NONCE_CACHE_TTL_MS;
    dev.parkedGuardNonceJournal = dev.parkedGuardNonceJournal.filter(item => item && item.expiresAt >= expiredNonceWindowStart);
    if (dev.parkedGuardNonceJournal.some(item => item.nonceDigest === nonceDigest)) {
        return { ok: false, error: 'Replay detected (duplicate nonce).' };
    }

    let canonicalPayload;
    if (msg.canonical_payload == null) {
        canonicalPayload = [
            JSON.stringify({ action, nonce, commandType, requestId, payloadHash: msg.payload_hash || null }, sortKeysDeep),
            requestId,
            commandTimestamp,
            action,
            String(stateVersionTarget)
        ].join(':');
    } else {
        canonicalPayload = String(msg.canonical_payload);
    }

    let signatureBuffer;
    try {
        signatureBuffer = Buffer.from(signatureBase64, 'base64');
    } catch (e) {
        return { ok: false, error: 'Signature decode failed.' };
    }
    if (signatureBuffer.length < 16) return { ok: false, error: 'Signature missing or unsupported.' };

    const expected = crypto.createHmac('sha256', pairingSecret).update(canonicalPayload).digest();
    if (expected.length !== signatureBuffer.length || !crypto.timingSafeEqual(expected, signatureBuffer)) {
        return { ok: false, error: 'Signature verification failed.' };
    }

    dev.parkedGuardNonceJournal.push({ nonceDigest, expiresAt: commandTimestamp + PARKED_GUARD_NONCE_CACHE_TTL_MS });
    return { ok: true, action, requestId, nonce, stateVersionTarget, timestamp: commandTimestamp };
}

function sortKeysDeep(value) {
    if (Array.isArray(value)) return value.map(sortKeysDeep);
    if (value && typeof value === 'object') {
        const result = {};
        for (const key of Object.keys(value).sort()) result[key] = sortKeysDeep(value[key]);
        return result;
    }
    return value;
}

function ensureParkedGuardPairing(dev) {
    return parkedGuardPairSecret(dev);
}

wss.on('connection', (ws, req) => {
    const urlParams = new URLSearchParams(req.url.split('?')[1]);
    const role = urlParams.get('role');
    const token = urlParams.get('token');

    let rawDevice = urlParams.get('deviceId') || urlParams.get('device') || 'myaura001';
    const deviceId = rawDevice.trim();

    if (!role) return reject(ws, 'BAD_HANDSHAKE', 'Missing system configuration role parameters.');
    if (deviceId && blacklist.has(deviceId)) return reject(ws, 'AUTHENTICATION_REVOKED', 'Blacklisted profile.');

    const dev = getDevice(deviceId);
    if (!dev) return reject(ws, 'INVALID_DEVICE', 'Device identifier rejected by server policy.');

    // ── PERMANENT BAN & LOCKOUT CHECK ──
    if (role !== 'admin' && role !== 'guest' && role !== 'summary_client') {
        if (dev.permanently_banned) {
            ws.send(JSON.stringify({ type: 'ERROR_BANNED', message: 'Device permanently banned.' }));
            setTimeout(() => { try{ws.close();}catch(e){} }, 500);
            return;
        }
        // Allow companion to connect even during lockout to send recovery code,
        // but the app should be told it is locked.
        if (dev.lockout_active && role !== 'companion') {
            return reject(ws, 'SECURITY_LOCKOUT', 'Administrative lockout active.');
        }
    }

    // ── 🔐 ADMIN OVERLORD PIPELINE ──
    if (role === 'admin') {
        const protocols = (req.headers['sec-websocket-protocol'] || '')
            .split(',')
            .map(item => item.trim())
            .filter(Boolean);

        const hasLeakyQueryAuth = urlParams.has('auth');
        const hasRequiredSubprotocol =
            protocols.length >= 2 &&
            protocols[0].toLowerCase() === 'admin' &&
            protocols[1].length > 0;

        if (!hasRequiredSubprotocol || hasLeakyQueryAuth) {
            ws.send(JSON.stringify({ type: 'auth_error' }));
            setTimeout(() => { try { ws.close(); } catch (e) {} }, 200);
            return;
        }

        let inputAuth = '';
        let decodeFailed = false;
        try {
            inputAuth = decodeURIComponent(protocols[1]);
        } catch (err) {
            decodeFailed = true;
        }

        if (decodeFailed || inputAuth.length === 0 || !safeStringEqual(inputAuth, ADMIN_PIN)) {
            ws.send(JSON.stringify({ type: 'auth_error' }));
            setTimeout(() => { try { ws.close(); } catch (e) {} }, 200);
            return;
        }
        adminClients.add(ws);
        ws.send(JSON.stringify({ type: 'handshake_ok', message: 'Ecosystem dashboard authenticated.' }));
        broadcastTopology();

        ws.on('message', (message) => {
            try {
                const command = JSON.parse(message);

    if (command.type === 'burn_token') {
        const targetDev = devices.get(command.device);
        if (targetDev) {
                        const tokenMeta = targetDev.guestTokens.get(command.token);
                        const tokenTypeLabel = (tokenMeta && tokenMeta.type === 'summary') ? 'SUMMARY LINK' : 'GUEST PASS';

                        if (tokenMeta) {
                            tokenMeta.burned = true;
                            targetDev.guestTokens.set(command.token, tokenMeta);
                            saveState();
                        }

                        if (targetDev.companion && targetDev.companion.readyState === WebSocket.OPEN) {
                            targetDev.companion.send(JSON.stringify({
                                type: 'token_burned',
                                token: command.token,
                                tokenType: tokenTypeLabel
                            }));
                        }
                    }
    }

                    if (command.type === 'permissions_update') {
                    const targetDev = devices.get(command.device);
                    if (targetDev) {
                        targetDev.guestPermissions = {
                            allowPlayback: command.allowPlayback !== false,
                            allowSuggestions: command.allowSuggestions !== false
                        };
                        saveState();
                        targetDev.guests.forEach(g => {
                            if (g.readyState === WebSocket.OPEN) {
                                g.send(JSON.stringify({
                                    type: 'permissions_update',
                                    allowPlayback: targetDev.guestPermissions.allowPlayback,
                                    allowSuggestions: targetDev.guestPermissions.allowSuggestions
                                }));
                            }
                        });
                    }
                }

                if (command.type === 'admin_ban_fingerprint') {
                    if (command.deviceFingerprint) {
                        fingerprintBlacklist.add(command.deviceFingerprint);
                        saveState();
                        const targetDev = devices.get(command.device);
                        if (targetDev) {
                            for (const [gWs, meta] of targetDev.guestMetadata.entries()) {
                                if (meta.fingerprint === command.deviceFingerprint) {
                                    try {
                                        gWs.send(JSON.stringify({ type: 'device_blocked', reason: 'ADMIN_PERMANENT_BAN' }));
                                        gWs.close();
                                    } catch(e) {}
                                    targetDev.guests.delete(gWs);
                                    targetDev.guestMetadata.delete(gWs);
                                }
                            }
                        }
                    }
                }

                if (command.type === 'admin_unban_fingerprint') {
                    if (command.deviceFingerprint) {
                        fingerprintBlacklist.delete(command.deviceFingerprint);
                        saveState();
                    }
                }

                if (command.type === 'admin_unban_all_fingerprints') {
                    blacklist.clear();
                    fingerprintBlacklist.clear();
                    for (const [deviceId, d] of devices.entries()) {
                        d.hud_banned = false;
                        d.companion_banned = false;
                        d.permanently_banned = false;
                        d.lockout_active = false;

                        if (d.companion && d.companion.readyState === WebSocket.OPEN) {
                            d.companion.send(JSON.stringify({ type: 'lockout_cleared' }));
                        }
                    }
                    saveState();
                    broadcastTopology();
                }

                if (command.type === 'admin_kick_all_guests') {
                    const targetDev = devices.get(command.device);
                    if (targetDev) {
                        targetDev.guests.forEach(gWs => {
                            try {
                                gWs.send(JSON.stringify({ type: 'banned', reason: 'ADMIN_FORCE_KICK_ALL' }));
                                gWs.close();
                            } catch(e) {}
                        });
                        targetDev.guests.clear();
                        targetDev.guestMetadata.clear();
                    }
                }

                if (command.type === 'cmd_spotify_play') {
                    const targetDev = devices.get(command.device);
                    if (targetDev) {
                        targetDev.currentTrack = command.track || { uri: command.uri };
                        if (targetDev.headunit && targetDev.headunit.readyState === WebSocket.OPEN) targetDev.headunit.send(JSON.stringify(command));
                        if (targetDev.companion && targetDev.companion.readyState === WebSocket.OPEN) targetDev.companion.send(JSON.stringify(command));
                        if (targetDev.players) {
                            targetDev.players.forEach(p => { if (p.readyState === WebSocket.OPEN) p.send(JSON.stringify(command)); });
                        }
                        targetDev.guests.forEach(g => { if (g.readyState === WebSocket.OPEN) g.send(JSON.stringify(command)); });
                    }
                }

                if (command.type === 'toggle_parked_guard') {
                    const targetDev = devices.get(command.device);
                    if (targetDev) {
                        targetDev.parkedGuardActive = command.active;
                        if (command.active && targetDev.hudState) {
                            targetDev.parkedCoords = { lat: targetDev.hudState.lat || 0, lng: targetDev.hudState.lng || 0 };
                        }
                        saveState();
                    }
                }

                if (command.type === 'admin_block_device') {
                    blacklist.add(command.device);
                    persistSecurityFlag(command.device, 'permanently_banned', true);
                    saveState();
                }
                if (command.type === 'admin_allow_device') {
                    blacklist.delete(command.device);
                    persistSecurityFlag(command.device, 'permanently_banned', false);
                    saveState();
                }

                // Modified kill_node
                if (command.type === 'kill_node') {
                    const targetDev = devices.get(command.device);
                    if (targetDev) {
                        if (command.node === 'hud') {
                            targetDev.hud_banned = true;
                            persistSecurityFlag(command.device, 'hud_banned', true);
                            if (targetDev.headunit) {
                                targetDev.headunit.send(JSON.stringify({type: 'ERROR_BANNED', message: 'HUD node banned'}));
                                setTimeout(() => targetDev.headunit?.close(), 100);
                            }
                        }
                        if (command.node === 'companion') {
                            targetDev.companion_banned = true;
                            persistSecurityFlag(command.device, 'companion_banned', true);
                            if (targetDev.companion) {
                                targetDev.companion.send(JSON.stringify({type: 'ERROR_BANNED', message: 'Companion node banned'}));
                                setTimeout(() => targetDev.companion?.close(), 100);
                            }
                        }
                        if (command.node === 'full_ban') {
                            targetDev.permanently_banned = true;
                            persistSecurityFlag(command.device, 'permanently_banned', true);
                            if (targetDev.headunit) {
                                targetDev.headunit.send(JSON.stringify({type: 'ERROR_BANNED', message: 'Device permanently banned'}));
                                setTimeout(() => targetDev.headunit?.close(), 100);
                            }
                            if (targetDev.companion) {
                                targetDev.companion.send(JSON.stringify({type: 'ERROR_BANNED', message: 'Device permanently banned'}));
                                setTimeout(() => targetDev.companion?.close(), 100);
                            }
                        }
                        saveState();
                    }
                }

                if (command.type === 'revoke_node_ban') {
                    const targetDev = devices.get(command.device);
                    if (targetDev) {
                        if (command.node === 'hud') targetDev.hud_banned = false;
                        if (command.node === 'companion') targetDev.companion_banned = false;
                        if (command.node === 'full_ban') targetDev.permanently_banned = false;
                        saveState();
                    }
                }

                // ── SECURE PURGE ADDITIVE HANDLERS ──
                if (command.type === 'admin_init_purge') {
                    const targetDev = devices.get(command.device);
                    if (targetDev && safeStringEqual(command.master_pin, MASTER_PIN)) {
                        targetDev.pendingWipe.active = true;
                        targetDev.pendingWipe.codeA = generateCodeA();
                        targetDev.pendingWipe.codeB = generateCodeB();
                        targetDev.pendingWipe.approved = false;
                        targetDev.pendingWipe.huBackupReceived = false;
                        targetDev.pendingWipe.compBackupReceived = false;
                        saveState();

                        console.log(`[SECURE PURGE] Initiated (code and sensitive details redacted).`);

                        ws.send(JSON.stringify({
                            type: 'secure_purge_code_a',
                            code_a: targetDev.pendingWipe.codeA,
                            device: command.device
                        }));

                        if (targetDev.companion && targetDev.companion.readyState === WebSocket.OPEN) {
                            targetDev.companion.send(JSON.stringify({ type: 'purge_handshake_challenge' }));
                        }
                    } else {
                         ws.send(JSON.stringify({ type: 'secure_purge_error', message: 'Invalid Master PIN or Device' }));
                    }
                }

                if (command.type === 'admin_approve_purge') {
                     const targetDev = devices.get(command.device);
                     if (targetDev && targetDev.pendingWipe.active) {
                         if (command.decision === 'YES') {
                             targetDev.pendingWipe.approved = true;
                             saveState();
                             ws.send(JSON.stringify({ type: 'secure_purge_code_b', code_b: targetDev.pendingWipe.codeB, device: command.device }));

                             if (targetDev.companion && targetDev.companion.readyState === WebSocket.OPEN) {
                                 targetDev.companion.send(JSON.stringify({ type: 'request_code_b_entry' }));
                             }

                             if (targetDev.headunit && targetDev.headunit.readyState === WebSocket.OPEN) {
                                  targetDev.headunit.send(JSON.stringify({ type: 'request_backup' }));
                             }
                             if (targetDev.companion && targetDev.companion.readyState === WebSocket.OPEN) {
                                  targetDev.companion.send(JSON.stringify({ type: 'request_backup' }));
                             }
                         } else {
                             targetDev.pendingWipe.active = false;
                             saveState();
                             triggerLockout(targetDev, command.device);
                         }
                     }
                }

                if (command.type === 'verify_purge_code_b') {
                    const targetDev = devices.get(command.device);
                    if (targetDev && targetDev.pendingWipe.active && targetDev.pendingWipe.approved) {
                        if (command.code_b === targetDev.pendingWipe.codeB) {
                            if (targetDev.pendingWipe.huBackupReceived && targetDev.pendingWipe.compBackupReceived) {
                                if (targetDev.headunit && targetDev.headunit.readyState === WebSocket.OPEN) {
                                    targetDev.headunit.send(JSON.stringify({ type: 'execute_wipe' }));
                                }
                                if (targetDev.companion && targetDev.companion.readyState === WebSocket.OPEN) {
                                    targetDev.companion.send(JSON.stringify({ type: 'execute_wipe' }));
                                }
                                targetDev.pendingWipe.active = false;
                                saveState();
                                ws.send(JSON.stringify({ type: 'secure_purge_success', message: 'Wipe executed.' }));
                            } else {
                                ws.send(JSON.stringify({ type: 'secure_purge_error', message: 'Backups incomplete. Please wait for telemetry capture.' }));
                                if (targetDev.companion && targetDev.companion.readyState === WebSocket.OPEN) {
                                    targetDev.companion.send(JSON.stringify({ type: 'secure_purge_error', message: 'Backups incomplete. System wipe delayed.' }));
                                }
                            }
                        } else {
                             targetDev.pendingWipe.active = false;
                             saveState();
                             triggerLockout(targetDev, command.device);
                        }
                    }
                }

                if (command.type === 'admin_panic_purge') {
                    if (!safeStringEqual(command.master_pin, MASTER_PIN)) {
                        ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin PIN.' }));
                        return;
                    }
                    for (const [, targetDev] of devices.entries()) {
                        if (targetDev.companion && targetDev.companion.readyState === WebSocket.OPEN) {
                            targetDev.companion.send(JSON.stringify({ type: 'purge_request_approved' }));
                        }
                    }
                }

                if (command.type === 'admin_emergency_disarm_parked_guard') {
                    const targetDev = devices.get(command.device);
                    if (!targetDev) {
                        ws.send(JSON.stringify({ type: 'error', message: 'Device not found.' }));
                    } else if (!safeStringEqual(command.master_pin || '', MASTER_PIN)) {
                        ws.send(JSON.stringify({ type: 'error', message: 'Invalid master PIN for emergency disarm.' }));
                    } else {
                        targetDev.parkedGuardState = 'DISARMED';
                        targetDev.parkedGuardActive = false;
                        targetDev.parkedGuardDisarmedAt = Date.now();
                        targetDev.parkedGuardStateVersion = (targetDev.parkedGuardStateVersion || 0) + 1;
                        enqueueParkedGuardAudit(targetDev, { action: 'emergency_disarm', result: 'accepted', actor: 'admin', reason: 'master_pin_emergency_override', request_id: command.request_id || null });
                        saveState();
                        broadcastTopology();
                        if (targetDev.companion && targetDev.companion.readyState === WebSocket.OPEN) {
                            targetDev.companion.send(JSON.stringify({ type: 'parked_guard_state', device: command.device, active: false, state: 'DISARMED', emergency: true, security_status: 200, result: 'accepted', reason: 'Emergency disarm executed under admin authority.', request_id: command.request_id || null }));
                        }
                        if (targetDev.headunit && targetDev.headunit.readyState === WebSocket.OPEN) {
                            targetDev.headunit.send(JSON.stringify({ type: 'parked_guard_state', device: command.device, active: false, state: 'DISARMED', emergency: true }));
                        }
                        ws.send(JSON.stringify({ type: 'secure_purge_success', message: 'Emergency Parked Guard disarm completed.', device: command.device }));
                    }
                    return;
                }

                if (command.type === 'force_unlock') {
                    const targetDev = devices.get(command.device);
                    if (targetDev) {
                         targetDev.lockout_active = false;
                         targetDev.recovery_code = null;
                         saveState();

                         if (targetDev.companion && targetDev.companion.readyState === WebSocket.OPEN) {
                             targetDev.companion.send(JSON.stringify({ type: 'lockout_cleared' }));
                         }

                         broadcastTopology();
                    }
                }

                broadcastTopology();
            } catch (err) { console.error("[SERVER] message handler error:", err); }
        });

        ws.on('close', () => adminClients.delete(ws));
        return;
    }

    function triggerLockout(targetDev, deviceId) {
        targetDev.lockout_active = true;
        persistSecurityFlag(deviceId, 'lockout_active', true);
        targetDev.recovery_code = generateRecoveryCode();
        saveState();


        adminClients.forEach(admin => {
            if (admin.readyState === WebSocket.OPEN) {
                admin.send(JSON.stringify({ type: 'lockout_recovery_code', device: deviceId, code: targetDev.recovery_code }));
            }
        });

        const lockoutPacket = JSON.stringify({ type: 'trigger_lockout', lockout_active: true });

        if (targetDev.headunit && targetDev.headunit.readyState === WebSocket.OPEN) {
            targetDev.headunit.send(lockoutPacket);
        }
        if (targetDev.companion && targetDev.companion.readyState === WebSocket.OPEN) {
            targetDev.companion.send(lockoutPacket);
        }
        broadcastTopology();
    }

    // ── 🎵 GUEST PASSENGER NEXUS ──
    if (role === 'guest') {
        if (!token || !dev.guestTokens.has(token)) {
            return reject(ws, 'SECURITY_VIOLATION', 'Invalid guest token.');
        }

        const tokenMeta = dev.guestTokens.get(token);
        if (tokenMeta.burned || (tokenMeta.expiresAt && Date.now() > tokenMeta.expiresAt)) {
            return reject(ws, 'SECURITY_VIOLATION', 'Guest token is burned or expired.');
        }

        // Keep token valid for the session; do not burn on connect.
        dev.guestTokens.set(token, tokenMeta);
        saveState();
        broadcastTopology();

        dev.guests.add(ws);
        // Store token on the socket for JIT validation
        ws.guestToken = token;

        ws.send(JSON.stringify({
            type: 'permissions_update',
            allowPlayback: dev.guestPermissions.allowPlayback,
            allowSuggestions: dev.guestPermissions.allowSuggestions
        }));


        ws.send(JSON.stringify({
            type: 'permissions_update',
            allowPlayback: dev.guestPermissions.allowPlayback,
            allowSuggestions: dev.guestPermissions.allowSuggestions
        }));

        if (dev.hudState) ws.send(JSON.stringify(dev.hudState));
        if (dev.currentTrack) ws.send(JSON.stringify({ type: 'cmd_spotify_play', track: dev.currentTrack }));

        ws.on('message', async (message) => {
            try {
                const msg = JSON.parse(message);
                if (!msg || typeof msg !== 'object' || Array.isArray(msg)) throw new Error('bad event');

                // JIT Validation: Check if token has expired while connected
                if (ws.guestToken) {
                    const tokenMeta = dev.guestTokens.get(ws.guestToken);
                    if (!tokenMeta || (tokenMeta.expiresAt && Date.now() > tokenMeta.expiresAt) || tokenMeta.burned) {
                        reject(ws, 'SECURITY_VIOLATION', 'Session token expired or revoked.');
                        return;
                    }
                }

                interceptTelemetryTransaction(`GUEST(${deviceId.substring(0,4)})`, 'SERVER', msg);


                if (msg.type === 'guest_auth') {
                    const fp = msg.deviceFingerprint || '';
                    if (fp && fingerprintBlacklist.has(fp) && !msg.isOwner) {
                        ws.send(JSON.stringify({ type: 'device_blocked', reason: 'ADMIN_PERMANENT_BAN' }));
                        ws.close();
                        return;
                    }

                    dev.guestMetadata.set(ws, {
                        name: msg.guestName || 'Anonymous',
                        fingerprint: fp,
                        isOwner: msg.isOwner === true,
                        connectedAt: Date.now()
                    });
                    ws.send(JSON.stringify({ type: 'auth_ok' }));
                    broadcastTopology();
                    return;
                }

                if (msg.type === 'search_spotify') {
                    const results = await querySpotifyTracks(msg.query);
                    ws.send(JSON.stringify({
                        type: 'search_spotify_results',
                        query: msg.query,
                        tracks: results
                    }));
                    return;
                }


                if (msg.type === 'cmd_music' || msg.type === 'cmd_panic' || msg.type === 'cmd_volume' || msg.type === 'cmd_trigger_failover' || msg.type === 'toggle_parked_guard') {
                    if (!dev.guestPermissions.allowPlayback) {
                        ws.send(JSON.stringify({ type: 'error', message: 'Guest permission denied.' }));
                        return;
                    }
                    if (dev.headunit && dev.headunit.readyState === WebSocket.OPEN) dev.headunit.send(JSON.stringify(msg));
                    if (dev.companion && dev.companion.readyState === WebSocket.OPEN) dev.companion.send(JSON.stringify(msg));
                    return;
                }

                if (msg.type === 'cmd_guest_suggest_song') {
                    if (!dev.guestPermissions.allowSuggestions) {
                        ws.send(JSON.stringify({ type: 'error', message: 'Guest permission denied.' }));
                        return;
                    }
                    // Forward only the curated subset of the request body.
                    const forwarded = {
                        type: msg.type,
                        suggestion: msg.suggestion,
                        track: msg.track,
                        uri: msg.uri
                    };
                    adminClients.forEach(admin => {
                        if (admin.readyState === WebSocket.OPEN) admin.send(JSON.stringify(forwarded));
                    });
                    if (dev.companion && dev.companion.readyState === WebSocket.OPEN) {
                        dev.companion.send(JSON.stringify(forwarded));
                    }
                    return;
                }
            } catch (err) { console.error("[SERVER] message handler error:", err); }
        });

        ws.on('close', () => {
            dev.guests.delete(ws);
            dev.guestMetadata.delete(ws);
            broadcastTopology();
        });
        return;
    }

    // ── 🏎️ HEADUNIT TELEMETRY CORE ──
    if (role === 'headunit') {
        const secret = urlParams.get('secret');
        const legacyAllowed = (process.env.PAIRING_REQUIRED !== 'true');
        if (legacyAllowed && secret === GLOBAL_SECRET) {
            // legacy path
        } else if (process.env.PAIRING_REQUIRED === 'true') {
            if (!dev.paired || secret !== dev.relayCredential) return reject(ws, 'SECURITY_VIOLATION', 'Unpaired or invalid headunit credential.');
        } else if (secret !== GLOBAL_SECRET) {
            return reject(ws, 'SECURITY_VIOLATION', 'Invalid access token.');
        }
        if (dev.hud_banned) return reject(ws, 'NODE_LOCKED', 'Headunit authorization suspended.');

        if (dev.headunit) {
            dev.headunit.send(JSON.stringify({ type: 'error', message: 'Takeover instance running.' }));
            dev.headunit.close();
        }

        dev.headunit = ws;
        console.log(`[HEADUNIT MODULE] Cluster Track Active: ${deviceId}`);
        broadcastTopology();

        ws.on('message', (message) => {
            try {
                const msg = JSON.parse(message);
                if (msg && msg.type === 'ping') return;

                interceptTelemetryTransaction(`HUD_UNIT(${deviceId.substring(0,4)})`, 'SERVER', msg);

                if (msg.type === 'state') {
                    dev.hudState = msg;
                    dev.hudLastSeen = Date.now();

                    if (msg.music_title || msg.title) {
                        dev.currentTrack = {
                            title: msg.music_title || msg.title,
                            artist: msg.music_artist || msg.artist,
                            cover: msg.music_cover || msg.cover || msg.album_art
                        };
                    }

                    const fuel = parseFloat(msg.fuel_percent) || 100;
                    const battery = parseFloat(msg.battery_voltage) || 12.6;

                    if ((fuel < 15 || battery < 11.8) && dev.companion && dev.companion.readyState === WebSocket.OPEN) {
                        dev.companion.send(JSON.stringify({
                            type: 'threshold_alert',
                            fuel,
                            battery,
                            message: fuel < 15 ? `⚠️ Low Fuel Warning: ${fuel}% remaining!` : `⚠️ Low Battery Warning: ${battery}V!`
                        }));
                    }

                    if (dev.parkedGuardActive && isFinite(msg.speed) && Number(msg.speed) > 5) {
                        const now = Date.now();
                        if (!dev.parkedGuardLastAlertAt || now - dev.parkedGuardLastAlertAt >= 10000) {
                            dev.parkedGuardLastAlertAt = now;
                            dev.parkedGuardAlertCount = (dev.parkedGuardAlertCount || 0) + 1;
                            dev.parkedGuardState = 'MOVEMENT_ALERT';
                            dev.parkedGuardStateVersion = (dev.parkedGuardStateVersion || 0) + 1;
                            if (dev.companion && dev.companion.readyState === WebSocket.OPEN) {
                                dev.companion.send(JSON.stringify({
                                    type: 'parked_guard_alert',
                                    alert_id: `pga_${now}`,
                                    state_version: dev.parkedGuardStateVersion,
                                    server_now: now,
                                    message: `🚨 ANTI-THEFT ALERT: Vehicle movement detected (${msg.speed} km/h) while Parked Guard is ACTIVE!`
                                }));
                            }
                            if (!dev.parkedGuardLastSirenAt || now - dev.parkedGuardLastSirenAt >= 2000) {
                                dev.parkedGuardLastSirenAt = now;
                                dev.parkedGuardEscalationLevel = Math.min(3, (dev.parkedGuardEscalationLevel || 0) + 1);
                                enqueueParkedGuardAudit(dev, { action: 'move_detected', result: 'accepted', reason: 'escalating_auto_siren', detail: `movement at ${msg.speed} km/h`, request_id: null });
                                if (dev.headunit && dev.headunit.readyState === WebSocket.OPEN) {
                                    dev.headunit.send(JSON.stringify({ type: 'trigger_siren', reason: 'PARKED_GUARD_MOVEMENT', alert_id: `pga_${now}` }));
                                }
                            }
                            saveState();
                        }
                    }

                    dev.guests.forEach(g => { if (g.readyState === WebSocket.OPEN) g.send(JSON.stringify(msg)); });
                    broadcastTopology();
                } else if (msg.type === 'speed_update') {
                    if (dev.hudState) {
                        dev.hudState.speed = msg.speed;
                    }
                    if (dev.companion && dev.companion.readyState === WebSocket.OPEN) {
                        dev.companion.send(JSON.stringify(msg));
                    }
                }

                if (msg.type === 'backup_data') {
                    dev.pendingWipe.huBackupReceived = true;
                    saveState();
                    adminClients.forEach(admin => {
                        if (admin.readyState === WebSocket.OPEN) {
                            admin.send(JSON.stringify({ type: 'device_backup', device: deviceId, node: 'headunit', data: msg.data }));
                        }
                    });
                }
            } catch (err) { console.error("[SERVER] message handler error:", err); }
        });

        ws.on('close', () => {
            if (dev.headunit === ws) {
                dev.headunit = null;
                dev.hudLastSeen = Date.now();
            }
            broadcastTopology();
        });
        return;
    }

    // ── 📱 COMPANION CONTROLLER ──
    if (role === 'companion') {
        const secret = urlParams.get('secret');
        if (process.env.PAIRING_REQUIRED === 'true') {
            if (!dev.paired || secret !== dev.relayCredential) return reject(ws, 'SECURITY_VIOLATION', 'Unpaired or invalid companion credential.');
        } else if (secret !== GLOBAL_SECRET) {
            return reject(ws, 'SECURITY_VIOLATION', 'Companion key missing.');
        }
        if (dev.companion_banned) return reject(ws, 'NODE_LOCKED', 'Companion suspended.');

        if (dev.companion) { try { dev.companion.close(); } catch(e){} }

        dev.companion = ws;
        console.log(`[COMPANION MOBILE] Remote Deck Sync: ${deviceId}`);

        if (!dev.lockout_active) {
            ws.send(JSON.stringify({ type: 'lockout_cleared' }));
        }

        if (dev.parkedGuardSigningEnabled === false || !dev.parkedGuardPairingSecret) {
            ensureParkedGuardPairing(dev);
            if (dev.parkedGuardPairingSecret) {
                ws.send(JSON.stringify({
                    type: 'parked_guard_pairing',
                    device: deviceId,
                    signing_method: 'hmac-sha256',
                    pairing_key: dev.parkedGuardPairingSecret,
                    created_at: dev.parkedGuardPairingCreatedAt,
                    warning: 'Pairing secret delivered only to the authenticated companion node.'
                }));
            }
        } else {
            ws.send(JSON.stringify({
                type: 'parked_guard_pairing',
                device: deviceId,
                signing_method: 'hmac-sha256',
                pairing_available: true,
                rotated: false
            }));
        }

        broadcastTopology();

        ws.on('message', (message) => {
            try {
                const msg = JSON.parse(message);
                interceptTelemetryTransaction(`PHONE_APP(${deviceId.substring(0,4)})`, 'SERVER', msg);

                if (!msg || typeof msg !== 'object' || Array.isArray(msg) || typeof msg.type !== 'string' || msg.type.length === 0 || msg.type.length > 64) {
                    console.warn('[COMPANION DROP] Rejected malformed control frame.');
                    return;
                }

                if (dev.lockout_active && msg.type !== 'verify_recovery_code') {
                    ws.send(JSON.stringify({ type: 'error', message: 'Device is locked. Recovery code required.' }));
                    return;
                }

                const PARKED_GUARD_COMMANDS = new Set([
                    'parked_guard_arm',
                    'parked_guard_disarm',
                    'parked_guard_ack',
                    'parked_guard_alert_ack',
                    'request_parked_guard_state',
                    'toggle_parked_guard'
                ]);

                if (PARKED_GUARD_COMMANDS.has(msg.type)) {
                    const companionAuthority = (dev.companion === ws);
                    const requestId = 'pg_' + crypto.randomUUID();
                    const requestedActive = (msg.type === 'parked_guard_disarm')
                        ? false
                        : (msg.type === 'parked_guard_arm' || msg.type === 'toggle_parked_guard' ? true : !!msg.active);

                    const pushAudit = (result, detail) => {
                        const entry = {
                            at: Date.now(),
                            actor: 'companion:' + deviceId.substring(0, 4),
                            type: msg.type,
                            result,
                            detail: String(detail || '').slice(0, 300),
                            request_id: requestId,
                            state_version: dev.parkedGuardStateVersion || 0
                        };
                        dev.parkedGuardAuditTrail = (dev.parkedGuardAuditTrail || []).concat([entry]).slice(-100);
                        try { dev.parkedGuardLastResult = Object.assign({}, entry); } catch (e) {}
                    };

                    const capabilities = {
                        arm: companionAuthority,
                        disarm: false,
                        disarmRequiresSignature: true,
                        guestCommandsAllowed: false,
                        emergencyOverrideAdminOnly: true
                    };

                    const response = (result, status, reason, extra) => {
                        const payload = Object.assign({
                            type: 'parked_guard_state',
                            device: deviceId,
                            active: !!dev.parkedGuardActive,
                            state: dev.parkedGuardState,
                            state_version: dev.parkedGuardStateVersion || 0,
                            changed_at: Date.now(),
                            security_status: status,
                            result,
                            reason,
                            request_id: requestId,
                            capabilities,
                            policy: {
                                movementThresholdKph: 5,
                                armingRequiresHudTelemetry: true,
                                companionDisarmMode: 'signed_and_replay_protected'
                            }
                        }, extra || {});
                        ws.send(JSON.stringify(payload));
                        ws.send(JSON.stringify({ type: 'parked_guard_update', device: deviceId, active: !!dev.parkedGuardActive, state: dev.parkedGuardState, state_version: dev.parkedGuardStateVersion || 0, changed_at: Date.now() }));
                        if (result === 'accepted') {
                            if (dev.companion && dev.companion.readyState === WebSocket.OPEN && dev.companion !== ws) dev.companion.send(JSON.stringify(payload));
                            if (dev.headunit && dev.headunit.readyState === WebSocket.OPEN) dev.headunit.send(JSON.stringify({ type: 'parked_guard_state', device: deviceId, active: !!dev.parkedGuardActive, state: dev.parkedGuardState, state_version: dev.parkedGuardStateVersion || 0 }));
                        }
                    };

                    if (!companionAuthority) {
                        pushAudit('rejected', 'Companion socket not authoritative');
                        response('rejected', 403, 'Only the paired companion may issue Parked Guard commands.');
                        broadcastTopology();
                        return;
                    }

                    if (msg.type === 'request_parked_guard_state') {
                        pushAudit('accepted', 'Companion requested authoritative snapshot.');
                        saveState();
                        response('accepted', 200, 'Authoritative Parked Guard snapshot.');
                        broadcastTopology();
                        return;
                    }

                    if (msg.type === 'parked_guard_alert_ack') {
                        dev.parkedGuardLastAckAt = Date.now();
                        pushAudit('accepted', 'software acknowledgement received (count: ' + (dev.parkedGuardAlertCount || 0) + ').');
                        saveState();
                        response('accepted', 200, 'Alert acknowledgement recorded.');
                        dev.parkedGuardLastResult = { type: 'alert_ack', at: Date.now(), request_id: requestId, count: dev.parkedGuardAlertCount || 0 };
                        broadcastTopology();
                        return;
                    }

                    if (msg.type === 'parked_guard_ack') {
                        dev.parkedGuardLastAckAt = Date.now();
                        pushAudit('accepted', 'Software acknowledgement received.');
                        saveState();
                        response('accepted', 200, 'Guard acknowledgement recorded.');
                        broadcastTopology();
                        return;
                    }

                    if (msg.type === 'parked_guard_disarm' || (msg.type === 'toggle_parked_guard' && !requestedActive)) {
                        pushAudit('rejected', 'Unsigned disarm blocked by server authority.');
                        dev.parkedGuardLastResult = { type: msg.type, at: Date.now(), request_id: requestId, result: 'rejected_unsigned_disarm' };
                        response('rejected', 403, 'Companion disarm requires a signed, replay-protected command (Phase 2B not yet enabled).');
                        broadcastTopology();
                        return;
                    }

                    if (requestedActive) {
                        const speed = (dev.hudState && isFinite(dev.hudState.speed)) ? Number(dev.hudState.speed) : null;
                        const latitude = (dev.hudState && isFinite(dev.hudState.lat)) ? Number(dev.hudState.lat) : null;
                        const longitude = (dev.hudState && isFinite(dev.hudState.lng)) ? Number(dev.hudState.lng) : null;
                        if (speed === null) {
                            pushAudit('rejected', 'HUD telemetry unavailable.');
                            response('rejected', 412, 'Move the HUD online before arming Parked Guard.');
                            broadcastTopology();
                            return;
                        }
                        if (speed > 5) {
                            pushAudit('rejected', 'ignored guard arming because vehicle is moving at ' + speed + ' km/h.');
                            response('rejected', 409, 'Parked Guard can only be armed while parked (threshold 5 km/h).', { telemetry: { speed, threshold: 5 } });
                            broadcastTopology();
                            return;
                        }
                        dev.parkedGuardState = 'ARMED';
                        dev.parkedGuardActive = true;
                        dev.parkedGuardArmedAt = Date.now();
                        dev.parkedCoords = (latitude !== null && longitude !== null)
                            ? { lat: latitude, lng: longitude, speed, capturedAt: Date.now() }
                            : null;
                        dev.parkedGuardAnchor = dev.parkedCoords;
                        dev.parkedGuardStateVersion = (dev.parkedGuardStateVersion || 0) + 1;
                        dev.parkedGuardLastResult = { type: 'arm', at: Date.now(), request_id: requestId, result: 'accepted', security_status: 'unsigned_arm_policy_phase_2a' };
                        pushAudit('accepted', 'armed at ' + latitude + ',' + longitude + '; speed ' + speed + ' km/h.');
                        saveState();
                        response('accepted', 200, 'Parked Guard armed. Security status remains digest-aware and disarm is signed-only.');
                        broadcastTopology();
                        return;
                    }

                    pushAudit('accepted', 'No state transition requested.');
                    response('accepted', 200, 'Authoritative Parked Guard snapshot.');
                    broadcastTopology();
                    return;
                }

                if (msg.type === 'parked_guard_signed_command') {
                    const companionAuthority = dev.companion === ws;
                    if (!companionAuthority) {
                        enqueueParkedGuardAudit(dev, { action: msg.action || msg.type, result: 'rejected', reason: 'client_not_authoritative', detail: 'Signed command rejected: non-companion socket.' });
                        ws.send(JSON.stringify({ type: 'parked_guard_state', device: deviceId, state: dev.parkedGuardState, security_status: 403, result: 'rejected', reason: 'Only the paired companion plane can issue commands.', request_id: msg.request_id || null }));
                        broadcastTopology();
                        return;
                    }
                    const verify = validateParkedGuardSignature(dev, msg);
                    if (!verify.ok) {
                        enqueueParkedGuardAudit(dev, { action: msg.action || msg.type, result: 'rejected', reason: 'signature_failure', detail: verify.error, request_id: msg.request_id || null });
                        ws.send(JSON.stringify({ type: 'parked_guard_state', device: deviceId, active: !!dev.parkedGuardActive, state: dev.parkedGuardState, state_version: dev.parkedGuardStateVersion || 0, security_status: 403, result: 'rejected', reason: verify.error, request_id: msg.request_id || null }));
                        broadcastTopology();
                        return;
                    }

                    const action = verify.action;
                    const requestId = verify.requestId;
                    dev.parkedGuardStateVersion = (dev.parkedGuardStateVersion || 0) + 1;
                    if (action === 'disarm' || action === 'off') {
                        dev.parkedGuardState = 'DISARMED';
                        dev.parkedGuardActive = false;
                        dev.parkedGuardDisarmedAt = Date.now();
                        enqueueParkedGuardAudit(dev, { action, result: 'accepted', reason: 'signed_disarm_accepted', request_id: requestId });
                    } else if (action === 'arm' || action === 'enforce_current' || action === 'on') {
                        if (!dev.hudState || !isFinite(dev.hudState.speed) || Number(dev.hudState.speed) > 5) {
                            enqueueParkedGuardAudit(dev, { action, result: 'rejected', reason: 'arming_policy_violation', detail: 'Telemetry required', request_id: requestId });
                            ws.send(JSON.stringify({ type: 'parked_guard_state', device: deviceId, active: !!dev.parkedGuardActive, state: dev.parkedGuardState, state_version: dev.parkedGuardStateVersion || 0, security_status: 409, result: 'rejected', reason: 'Park state requires speed <= 5km/h and active HUD telemetry.', request_id: requestId }));
                            broadcastTopology();
                            return;
                        }
                        dev.parkedGuardState = 'ARMED';
                        dev.parkedGuardActive = true;
                        dev.parkedGuardArmedAt = Date.now();
                        enqueueParkedGuardAudit(dev, { action, result: 'accepted', reason: 'signed_arm_accepted', request_id: requestId });
                    }
                    saveState();
                    ws.send(JSON.stringify({
                        type: 'parked_guard_state',
                        device: deviceId,
                        active: !!dev.parkedGuardActive,
                        state: dev.parkedGuardState,
                        state_version: dev.parkedGuardStateVersion || 0,
                        security_status: 200,
                        result: 'accepted',
                        reason: 'Signed command accepted.',
                        request_id: requestId,
                        audit_id: dev.parkedGuardLastResult && dev.parkedGuardLastResult.at
                    }));
                    broadcastTopology();
                    return;
                }

                // Legacy unsigned arm only. Signed disarm remains through `parked_guard_signed_command`.
                if (msg.type === 'parked_guard_arm' || msg.type === 'parked_guard_arm_unsigned') {
                    const companionAuthority = dev.companion === ws;
                    if (!companionAuthority) {
                        enqueueParkedGuardAudit(dev, { action: msg.type, result: 'rejected', reason: 'client_not_authoritative' });
                        ws.send(JSON.stringify({ type: 'parked_guard_state', device: deviceId, state: dev.parkedGuardState, security_status: 403, result: 'rejected', reason: 'Only the paired companion plane can issue commands.', request_id: msg.request_id || null }));
                        return;
                    }
                    if (!dev.hudState || !isFinite(dev.hudState.speed) || Number(dev.hudState.speed) > 5) {
                        enqueueParkedGuardAudit(dev, { action: msg.type, result: 'rejected', reason: 'arming_policy_violation' });
                        ws.send(JSON.stringify({ type: 'parked_guard_state', device: deviceId, active: !!dev.parkedGuardActive, state: dev.parkedGuardState, state_version: dev.parkedGuardStateVersion || 0, security_status: 409, result: 'rejected', reason: 'Park state requires speed <= 5 km/h', request_id: msg.request_id || null }));
                        return;
                    }
                    dev.parkedGuardState = 'ARMED';
                    dev.parkedGuardActive = true;
                    dev.parkedGuardArmedAt = Date.now();
                    dev.parkedGuardStateVersion = (dev.parkedGuardStateVersion || 0) + 1;
                    saveState();
                    enqueueParkedGuardAudit(dev, { action: msg.type, result: 'accepted', reason: 'unsigned_arm_policy_2a', request_id: msg.request_id || null });
                    ws.send(JSON.stringify({ type: 'parked_guard_state', device: deviceId, active: true, state: 'ARMED', security_status: 200, result: 'accepted', request_id: msg.request_id || null }));
                    broadcastTopology();
                    return;
                }

                if (msg.type === 'request_guest_token') {
    const guestToken = crypto.randomBytes(32).toString('hex').toUpperCase();
                    const tokenCategory = msg.tokenType || 'guest';
                    const expiresAt = Date.now() + (30 * 60 * 1000); // 30 minutes
                    dev.guestTokens.set(guestToken, {
                        type: tokenCategory,
                        burned: false,
                        expiresAt,
                        createdBy: 'companion'
                    });
                    saveState();
                    ws.send(JSON.stringify({ type: 'token_registered', token: guestToken, tokenType: tokenCategory }));
                    broadcastTopology();
                    return;
                }

                if (msg.type === 'state' || msg.type === 'companion_state') {
                    // Track companion state locally; never echo arbitrary peer traffic directly.
                    dev.companionState = msg;
                    broadcastTopology();
                } else if (COMPANION_TO_HEADUNIT_TYPES.has(msg.type)) {
                    // Registered companion directives only.
                    try {
                        if (dev.headunit && dev.headunit.readyState === WebSocket.OPEN) {
                            dev.headunit.send(JSON.stringify(msg));
                            interceptTelemetryTransaction('SERVER', `HUD_UNIT(${deviceId.substring(0,4)})`, msg);
                        }
                    } catch (err) {
                        console.error('[COMPANION FORWARD ERROR]:', err.message);
                    }
                } else {
                    // No silent catch-all passthrough remains.
                    console.warn(`[COMPANION BLOCKED] Unknown forwarded type: ${msg.type}`);
                }

                if (msg.type === 'verify_purge_code_a') {
                     if (dev.pendingWipe.active && msg.code_a === dev.pendingWipe.codeA) {
                         adminClients.forEach(admin => {
                             if (admin.readyState === WebSocket.OPEN) {
                                 admin.send(JSON.stringify({ type: 'purge_request_approval', device: deviceId }));
                             }
                         });
                     } else {
                         triggerLockout(dev, deviceId);
                     }
                }

                if (msg.type === 'verify_recovery_code') {
                    if (dev.lockout_active) {
                        if (msg.code === dev.recovery_code) {
                            dev.lockout_active = false;
                            dev.recovery_code = null;
                            saveState();
                            ws.send(JSON.stringify({type: 'lockout_cleared'}));
                            broadcastTopology();
                        } else {
                            if (dev.headunit && dev.headunit.readyState === WebSocket.OPEN) {
                                dev.headunit.send(JSON.stringify({ type: 'trigger_siren' }));
                            }
                        }
                    }
                }

                if (msg.type === 'backup_data') {
                    dev.pendingWipe.compBackupReceived = true;
                    saveState();
                    adminClients.forEach(admin => {
                        if (admin.readyState === WebSocket.OPEN) {
                            admin.send(JSON.stringify({ type: 'device_backup', device: deviceId, node: 'companion', data: msg.data }));
                        }
                    });
                }
            } catch (err) { console.error("[SERVER] message handler error:", err); }
        });

        ws.on('close', () => {
            if (dev.companion === ws) dev.companion = null;
            broadcastTopology();
        });
        return;
    }

    // ── 📊 SUMMARY CLIENT PIPELINE ──
    if (role === 'summary_client') {
        if (!token || !dev.guestTokens.has(token)) {
            return reject(ws, 'SECURITY_VIOLATION', 'Invalid summary token.');
        }

        const tokenMeta = dev.guestTokens.get(token);

        // 1. Strict category check
        if (!tokenMeta || tokenMeta.type !== 'summary') {
            return reject(ws, 'SECURITY_VIOLATION', 'Summary token category mismatch.');
        }

        // 2. Expiration and revocation checks (No persistent active flag)
        if (tokenMeta.burned || (tokenMeta.expiresAt && Date.now() > tokenMeta.expiresAt)) {
            return reject(ws, 'SECURITY_VIOLATION', 'Summary token is burned or expired.');
        }

        // 3. Concurrency check: Disconnect stale session if same token reconnects
        for (const [activeWs, activeToken] of dev.summaryClients.entries()) {
            if (activeToken === token) {
                try {
                    activeWs.terminate();
                } catch (e) {}
                dev.summaryClients.delete(activeWs);
            }
        }

        // 4. Register active session
        dev.summaryClients.set(ws, token);
        ws.guestToken = token;
        broadcastTopology();

        // 5. Per-message runtime validation
        ws.on('message', async (message) => {
            try {
                if (ws.guestToken) {
                    const currentMeta = dev.guestTokens.get(ws.guestToken);
                    if (
                        !currentMeta ||
                        currentMeta.type !== 'summary' ||
                        currentMeta.burned ||
                        (currentMeta.expiresAt && Date.now() > currentMeta.expiresAt)
                    ) {
                        reject(ws, 'SECURITY_VIOLATION', 'Session token expired or revoked.');
                        return;
                    }
                }
            } catch (err) { console.error("[SERVER] message handler error:", err); }
        });

        ws.send(JSON.stringify({ type: 'handshake_ok', status: 'awaiting_companion_approval' }));

        ws.on('close', () => {
            dev.summaryClients.delete(ws);
            broadcastTopology();
        });
        return;
    }
});

// ── GUEST TOKEN GARBAGE COLLECTION ──
setInterval(() => {
    const now = Date.now();
    let changed = false;
    for (const [deviceId, dev] of devices.entries()) {
        if (!dev.guestTokens) continue;
        for (const [token, meta] of dev.guestTokens.entries()) {
            if (meta.expiresAt && now > meta.expiresAt) {
                dev.guestTokens.delete(token);
                changed = true;

                // Terminate any active session using this expired token
                dev.guests.forEach(guestWs => {
                    if (guestWs.guestToken === token) {
                        reject(guestWs, 'SECURITY_VIOLATION', 'Session token expired.');
                    }
                });

                dev.summaryClients.forEach((activeToken, activeWs) => {
                    if (activeToken === token) {
                        try {
                            reject(activeWs, 'SECURITY_VIOLATION', 'Summary session token expired.');
                        } catch (e) {}
                        dev.summaryClients.delete(activeWs);
                    }
                });
            }
        }
    }
    if (changed) {
        saveState();
        broadcastTopology();
        changed = false;
    }
}, 5 * 60 * 1000); // Reduced to 5-minute GC interval

server.listen(PORT, () => console.log(`🟢 DriveOS 2.0 Centralized Hybrid Cluster Network Core Online On: ${PORT}`));
