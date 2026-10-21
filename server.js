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
const GLOBAL_SECRET = process.env.RELAY_SECRET || runtimeSecrets.globalSecret;
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

function getDevice(id) {
    if (!devices.has(id)) {
        devices.set(id, {
            headunit: null,
            companion: null,
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

            const activeGuestsList = [];
            if (dev.guestMetadata) {
                for (const [, gMeta] of dev.guestMetadata.entries()) {
                    activeGuestsList.push({
                        connectedAt: gMeta.connectedAt || null,
                        isOwner: gMeta.isOwner === true
                    });
                }
            }

            data.push({
                id: deviceId,
                isBlacklisted: blacklist.has(deviceId),
                permanently_banned: dev.permanently_banned,
                lockout_active: dev.lockout_active,
                hud_banned: dev.hud_banned,
                companion_banned: dev.companion_banned,
                parkedGuardActive: dev.parkedGuardActive,
                activeGuests: dev.guests ? dev.guests.size : 0,
                connectedGuestsList: activeGuestsList,
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
    const packet = JSON.stringify({
        type: 'wiretap_intercept',
        sequence: String(globalLogSequence++).padStart(4, '0'),
        origin, target, payload
    });
    adminClients.forEach(admin => { if (admin.readyState === WebSocket.OPEN) admin.send(packet); });
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
        const inputAuth = protocols.length > 1
            ? decodeURIComponent(protocols[1])
            : urlParams.get('auth');
        if (!safeStringEqual(inputAuth, ADMIN_PIN)) {
            ws.send(JSON.stringify({ type: 'auth_error' }));
            setTimeout(() => { try{ws.close();}catch(e){} }, 200);
            return;
        }
        adminClients.add(ws);
        ws.send(JSON.stringify({ type: 'handshake_ok', message: 'Ecosystem dashboard authenticated.' }));
        broadcastTopology();

        ws.on('message', (message) => {
            try {
                const command = JSON.parse(message);

    if (command.type === 'rotate_admin_token') {
        // REMOVED: rotate_admin_token moved to HTTPS POST endpoint
    }
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
            } catch (err) {}
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

        tokenMeta.burned = true;
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

                if (msg.type === 'cmd_guest_suggest_song') {
                    adminClients.forEach(admin => {
                        if (admin.readyState === WebSocket.OPEN) admin.send(JSON.stringify(msg));
                    });
                    if (dev.companion && dev.companion.readyState === WebSocket.OPEN) {
                        dev.companion.send(JSON.stringify(msg));
                    }
                    return;
                }

                if (msg.type === 'cmd_music' || msg.type === 'cmd_panic' || msg.type === 'cmd_volume' || msg.type === 'cmd_trigger_failover' || msg.type === 'toggle_parked_guard') {
                    if (dev.headunit && dev.headunit.readyState === WebSocket.OPEN) dev.headunit.send(JSON.stringify(msg));
                    if (dev.companion && dev.companion.readyState === WebSocket.OPEN) dev.companion.send(JSON.stringify(msg));
                    return;
                }
            } catch (err) {}
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
        if (secret !== GLOBAL_SECRET) return reject(ws, 'SECURITY_VIOLATION', 'Invalid access token.');
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

                    if (dev.parkedGuardActive && msg.speed > 5) {
                        if (dev.companion && dev.companion.readyState === WebSocket.OPEN) {
                            dev.companion.send(JSON.stringify({
                                type: 'parked_guard_alert',
                                message: `🚨 ANTI-THEFT ALERT: Vehicle movement detected (${msg.speed} km/h) while Parked Guard is ACTIVE!`
                            }));
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
            } catch (err) {}
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
        if (secret !== GLOBAL_SECRET) return reject(ws, 'SECURITY_VIOLATION', 'Companion key missing.');
        if (dev.companion_banned) return reject(ws, 'NODE_LOCKED', 'Companion suspended.');

        if (dev.companion) { try { dev.companion.close(); } catch(e){} }

        dev.companion = ws;
        console.log(`[COMPANION MOBILE] Remote Deck Sync: ${deviceId}`);

        if (!dev.lockout_active) {
            ws.send(JSON.stringify({ type: 'lockout_cleared' }));
        }

        broadcastTopology();

        ws.on('message', (message) => {
            try {
                const msg = JSON.parse(message);
                interceptTelemetryTransaction(`PHONE_APP(${deviceId.substring(0,4)})`, 'SERVER', msg);

                if (dev.lockout_active && msg.type !== 'verify_recovery_code') {
                    ws.send(JSON.stringify({ type: 'error', message: 'Device is locked. Recovery code required.' }));
                    return;
                }

                if (msg.type === 'toggle_parked_guard') {
                    dev.parkedGuardActive = msg.active;
                    saveState();
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
                    dev.companionState = msg;
                    broadcastTopology();
                } else {
                    if (dev.headunit && dev.headunit.readyState === WebSocket.OPEN) {
                        dev.headunit.send(JSON.stringify(msg));
                        interceptTelemetryTransaction('SERVER', `HUD_UNIT(${deviceId.substring(0,4)})`, msg);
                    }
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
            } catch (err) {}
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
        if (tokenMeta.burned || (tokenMeta.expiresAt && Date.now() > tokenMeta.expiresAt)) {
            return reject(ws, 'SECURITY_VIOLATION', 'Summary token is burned or expired.');
        }

        tokenMeta.burned = true;
        dev.guestTokens.set(token, tokenMeta);
        saveState();
        broadcastTopology();

        dev.summaryClients.set(ws, token);
        // Store token on the socket for JIT validation
        ws.guestToken = token;

        ws.on('message', async (message) => {
            try {
                // JIT Validation: Check if token has expired while connected
                if (ws.guestToken) {
                    const tokenMeta = dev.guestTokens.get(ws.guestToken);
                    if (!tokenMeta || (tokenMeta.expiresAt && Date.now() > tokenMeta.expiresAt) || tokenMeta.burned) {
                        reject(ws, 'SECURITY_VIOLATION', 'Session token expired or revoked.');
                        return;
                    }
                }
                // Summary clients normally don't send messages, but we validate if they do.
            } catch (err) {}
        });

        ws.send(JSON.stringify({ type: 'handshake_ok', status: 'awaiting_companion_approval' }));


        ws.on('close', () => {
            dev.summaryClients.delete(ws);
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
            }
        }
        if (changed) {
            saveState();
            changed = false;
        }
    }
}, 5 * 60 * 1000); // Reduced to 5-minute GC interval

server.listen(PORT, () => console.log(`🟢 DriveOS 2.0 Centralized Hybrid Cluster Network Core Online On: ${PORT}`));
