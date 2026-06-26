// ═══════════════════════════════════════════════
//  DriveOS 2.0 — Relay Server v2.1
//  - Master secret validation
//  - Role-based access control (headunit / companion / guest)
//  - Transparent pipe for encrypted export commands
//  - Device-based isolation
// ═══════════════════════════════════════════════

const express   = require('express');
const http      = require('http');
const WebSocket = require('ws');
const path      = require('path');

// ── CONFIG ──────────────────────────────────────
const GLOBAL_SECRET = process.env.DRIVEOS_SECRET || 'driveos2secret';
const PORT          = process.env.PORT || 3000;

// Commands that must pass through untouched — no parsing, no modification
const TRANSPARENT_PIPE_PREFIXES = [
  'cmd_export_challenge',
  'cmd_export_response',
  'cmd_export_data'
];

// ── STATE ────────────────────────────────────────
// devices['myaura001'] = {
//   headunit:   <WebSocket> | null,
//   companions: Set<WebSocket>,
//   guests:     Set<WebSocket>,
//   tokens:     Set<string>,
//   lastState:  {} | null
// }
const devices = {};

function getDevice(deviceId) {
  if (!devices[deviceId]) {
    devices[deviceId] = {
      headunit:   null,
      companions: new Set(),
      guests:     new Set(),
      tokens:     new Set(),
      lastState:  null
    };
  }
  return devices[deviceId];
}

// ── HELPERS ──────────────────────────────────────

// Check if a raw message string is an encrypted export command
// These must be forwarded as-is without JSON.parse
function isTransparentPipe(raw) {
  const str = raw.toString();
  return TRANSPARENT_PIPE_PREFIXES.some(prefix => str.startsWith(prefix));
}

// Safely parse JSON — returns null if invalid
function tryParse(raw) {
  try { return JSON.parse(raw); } catch { return null; }
}

// Reject a connection with a reason
function reject(ws, message, logMessage) {
  ws.send(JSON.stringify({ type: 'error', message }));
  ws.close();
  console.log(`[REJECTED] ${logMessage}`);
}

// ── EXPRESS ──────────────────────────────────────
const app    = express();
const server = http.createServer(app);

app.get('/guest', (req, res) => {
  res.sendFile(path.join(__dirname, 'guest.html'));
});

app.get('/', (req, res) => {
  res.send('DriveOS 2.0 Relay — Online');
});

// ── WEBSOCKET ─────────────────────────────────────
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
  const url    = new URL(req.url, 'http://localhost');
  const role   = url.searchParams.get('role');
  const device = url.searchParams.get('device');
  const secret = url.searchParams.get('secret');

  // ── STEP 1: MASTER SECRET CHECK ──
  // Every role except guest must pass the secret
  // Guest auth is handled via token after connection
  if (role !== 'guest') {
    if (secret !== GLOBAL_SECRET) {
      return reject(ws,
        'Invalid secret',
        `role=${role} device=${device} — bad secret, connection refused`
      );
    }
  }

  // ── STEP 2: DEVICE CHECK ──
  if (role !== 'guest' && !device) {
    return reject(ws,
      'Device ID required',
      `role=${role} — missing device ID`
    );
  }

  // ════════════════════════════════════════
  //  HEADUNIT
  //  wss://...?role=headunit&device=myaura001&secret=driveos2secret
  //  - Only one allowed per device
  //  - Only role allowed to PUSH state
  //  - Transparent pipe for encrypted export commands → Companion
  // ════════════════════════════════════════
  if (role === 'headunit') {
    const dev = getDevice(device);

    // Only one headunit per device allowed
    if (dev.headunit && dev.headunit.readyState === WebSocket.OPEN) {
      return reject(ws,
        'Headunit already connected for this device',
        `device=${device} — duplicate headunit rejected`
      );
    }

    dev.headunit = ws;
    console.log(`[HEADUNIT] Connected — device: ${device}`);
    ws.send(JSON.stringify({ type: 'headunit_auth_ok', message: 'Relay active' }));

    ws.on('message', (raw) => {

      // ── TRANSPARENT PIPE ──
      // Encrypted export commands go straight to companions, untouched
      if (isTransparentPipe(raw)) {
        console.log(`[PIPE] Headunit → Companion | device: ${device} | ${raw.toString().substring(0, 30)}...`);
        dev.companions.forEach(companion => {
          if (companion.readyState === WebSocket.OPEN) {
            companion.send(raw); // forward raw bytes, no modification
          }
        });
        return;
      }

      const data = tryParse(raw);
      if (!data) return;

      // ── STATE BROADCAST ──
      // Headunit pushes state → relay fans out to companions + guests
      if (data.type === 'state') {
        dev.lastState = data;
        const payload = JSON.stringify(data);

        dev.companions.forEach(c => {
          if (c.readyState === WebSocket.OPEN) c.send(payload);
        });

        dev.guests.forEach(g => {
          if (g.readyState === WebSocket.OPEN) g.send(payload);
        });
      }
    });

    ws.on('close', () => {
      dev.headunit = null;
      console.log(`[HEADUNIT] Disconnected — device: ${device}`);

      // Notify all connected clients
      const notice = JSON.stringify({ type: 'error', message: 'Headunit disconnected' });
      dev.companions.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(notice); });
      dev.guests.forEach(g => {     if (g.readyState === WebSocket.OPEN) g.send(notice); });
    });

    ws.on('error', err => {
      console.error(`[HEADUNIT] Error — device: ${device}:`, err.message);
    });

    return;
  }

  // ════════════════════════════════════════
  //  COMPANION APP
  //  wss://...?role=companion&device=myaura001&secret=driveos2secret
  //  - Can register guest tokens
  //  - Can PULL state
  //  - Receives transparent pipe commands from headunit
  //  - CANNOT push state to car
  // ════════════════════════════════════════
  if (role === 'companion') {
    const dev = getDevice(device);
    dev.companions.add(ws);

    console.log(`[COMPANION] Connected — device: ${device}`);
    ws.send(JSON.stringify({ type: 'companion_auth_ok', message: 'Companion connected' }));

    // Send last known state immediately
    if (dev.lastState) {
      ws.send(JSON.stringify(dev.lastState));
    }

    ws.on('message', (raw) => {

      // ── TRANSPARENT PIPE ──
      // Encrypted export responses go back to headunit, untouched
      if (isTransparentPipe(raw)) {
        console.log(`[PIPE] Companion → Headunit | device: ${device} | ${raw.toString().substring(0, 30)}...`);
        if (dev.headunit && dev.headunit.readyState === WebSocket.OPEN) {
          dev.headunit.send(raw); // forward raw bytes, no modification
        }
        return;
      }

      const data = tryParse(raw);
      if (!data) return;

      // ── TOKEN REGISTRATION ──
      // Companion registers a guest token before showing QR code
      // {"type":"register_token","token":"a3f9b2c1","device":"myaura001"}
      if (data.type === 'register_token') {
        if (!data.token || !data.device) {
          ws.send(JSON.stringify({ type: 'error', message: 'Token and device required' }));
          return;
        }
        const targetDev = getDevice(data.device);
        targetDev.tokens.add(data.token);
        console.log(`[TOKEN] Registered — token: ${data.token} | device: ${data.device}`);
        ws.send(JSON.stringify({ type: 'token_registered', token: data.token }));
        return;
      }

      // Block any attempt to push state from companion
      if (data.type === 'state') {
        ws.send(JSON.stringify({ type: 'error', message: 'Companions cannot push state' }));
        return;
      }
    });

    ws.on('close', () => {
      dev.companions.delete(ws);
      console.log(`[COMPANION] Disconnected — device: ${device}`);
    });

    ws.on('error', err => {
      console.error(`[COMPANION] Error — device: ${device}:`, err.message);
    });

    return;
  }

  // ════════════════════════════════════════
  //  GUEST PAGE
  //  wss://...?role=guest
  //  - Auth via JSON handshake after connect
  //  - Can ONLY receive state — cannot send anything to car
  //  - Token is one-time use
  // ════════════════════════════════════════
  if (role === 'guest') {
    console.log(`[GUEST] Connected — awaiting auth`);
    ws._authenticated = false;

    ws.on('message', (raw) => {
      const data = tryParse(raw);
      if (!data) return;

      // ── GUEST AUTH HANDSHAKE ──
      if (data.type === 'guest_auth') {
        const { device: gDevice, token } = data;

        if (!gDevice || !token) {
          ws.send(JSON.stringify({ type: 'error', message: 'Device and token required' }));
          ws.close();
          return;
        }

        const dev = getDevice(gDevice);

        if (!dev.tokens.has(token)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid Token' }));
          ws.close();
          console.log(`[GUEST] Auth failed — bad token: ${token} | device: ${gDevice}`);
          return;
        }

        // Authenticated
        ws._authenticated = true;
        ws._device        = gDevice;
        dev.guests.add(ws);
        dev.tokens.delete(token); // burned — one-time use

        console.log(`[GUEST] Authenticated — device: ${gDevice}`);
        ws.send(JSON.stringify({ type: 'auth_ok', message: 'Welcome to DriveOS 2.0' }));

        // Send last known state immediately so page isn't blank
        if (dev.lastState) {
          ws.send(JSON.stringify(dev.lastState));
        }

        return;
      }

      // ── BLOCK ALL OTHER MESSAGES FROM GUESTS ──
      // Guests can ONLY receive — they cannot send commands to the car
      ws.send(JSON.stringify({ type: 'error', message: 'Guests cannot send commands' }));
      console.log(`[GUEST] Blocked outbound message — type: ${data.type}`);
    });

    ws.on('close', () => {
      if (ws._device) {
        getDevice(ws._device).guests.delete(ws);
        console.log(`[GUEST] Disconnected — device: ${ws._device}`);
      }
    });

    ws.on('error', err => {
      console.error(`[GUEST] Error:`, err.message);
    });

    return;
  }

  // Unknown role — hard reject
  return reject(ws, 'Unknown role', `Unknown role: ${role}`);
});

// ── START ─────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`DriveOS 2.0 Relay running on port ${PORT}`);
});