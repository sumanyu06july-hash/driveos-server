// ═══════════════════════════════════════════════
//  DriveOS 2.0 — Relay Server v2.4 (Debug Mode)
//  - Master secret validation
//  - Role-based access control (headunit / companion / guest)
//  - Transparent pipe for encrypted export commands
//  - Device-based isolation
//  - Ghost connection override fix for headunits
//  - Companion-to-Headunit control command relay
//  - Enhanced Guest Auth Debug Logs
// ═══════════════════════════════════════════════

const express   = require('express');
const http      = require('http');
const WebSocket = require('ws');
const path      = require('path');

// ── CONFIG ──────────────────────────────────────
const GLOBAL_SECRET = process.env.DRIVEOS_SECRET || 'driveos2secret';
const PORT          = process.env.PORT || 3000;

const TRANSPARENT_PIPE_PREFIXES = [
  'cmd_export_challenge',
  'cmd_export_response',
  'cmd_export_data'
];

// ── STATE ────────────────────────────────────────
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
function isTransparentPipe(raw) {
  const str = raw.toString();
  return TRANSPARENT_PIPE_PREFIXES.some(prefix => str.startsWith(prefix));
}

function tryParse(raw) {
  try { return JSON.parse(raw); } catch { return null; }
}

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

  if (role !== 'guest') {
    if (secret !== GLOBAL_SECRET) {
      return reject(ws, 'Invalid secret', `role=${role} device=${device} — bad secret`);
    }
  }

  if (role !== 'guest' && !device) {
    return reject(ws, 'Device ID required', `role=${role} — missing device ID`);
  }

  // ════════════════════════════════════════
  //  HEADUNIT
  // ════════════════════════════════════════
  if (role === 'headunit') {
    const dev = getDevice(device);

    if (dev.headunit && dev.headunit.readyState === WebSocket.OPEN) {
      console.log(`[CONFLICT] Ghost headunit detected for device=${device}. Terminating old instance...`);
      try {
        dev.headunit.send(JSON.stringify({ type: 'error', message: 'Newer connection instance took over' }));
        dev.headunit.close();
      } catch (e) {
        console.error(`Failed to close ghost headunit: ${e.message}`);
      }
    }

    dev.headunit = ws;
    console.log(`[HEADUNIT] Connected — device: ${device}`);
    ws.send(JSON.stringify({ type: 'headunit_auth_ok', message: 'Relay active' }));

    ws.on('message', (raw) => {
      if (isTransparentPipe(raw)) {
        dev.companions.forEach(companion => {
          if (companion.readyState === WebSocket.OPEN) companion.send(raw);
        });
        return;
      }

      const data = tryParse(raw);
      if (!data) return;

      if (data.type === 'state') {
        dev.lastState = data;
        const payload = JSON.stringify(data);
        dev.companions.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(payload); });
        dev.guests.forEach(g => { if (g.readyState === WebSocket.OPEN) g.send(payload); });
      }
    });

    ws.on('close', () => {
      if (dev.headunit === ws) {
        dev.headunit = null;
        console.log(`[HEADUNIT] Disconnected — device: ${device}`);
        const notice = JSON.stringify({ type: 'error', message: 'Headunit disconnected' });
        dev.companions.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(notice); });
        dev.guests.forEach(g => { if (g.readyState === WebSocket.OPEN) g.send(notice); });
      }
    });

    return;
  }

  // ════════════════════════════════════════
  //  COMPANION APP
  // ════════════════════════════════════════
  if (role === 'companion') {
    const dev = getDevice(device);
    dev.companions.add(ws);

    console.log(`[COMPANION] Connected — device: ${device}`);
    ws.send(JSON.stringify({ type: 'companion_auth_ok', message: 'Companion connected' }));

    if (dev.lastState) {
      ws.send(JSON.stringify(dev.lastState));
    }

    ws.on('message', (raw) => {
      if (isTransparentPipe(raw)) {
        if (dev.headunit && dev.headunit.readyState === WebSocket.OPEN) {
          dev.headunit.send(raw);
        }
        return;
      }

      const data = tryParse(raw);
      if (!data) return;

      if (data.type === 'control' || data.type === 'command' || (data.type && data.type.startsWith('cmd_'))) {
        if (dev.headunit && dev.headunit.readyState === WebSocket.OPEN) {
          console.log(`[CONTROL] Relaying companion action (${data.type}) to headunit for device: ${device}`);
          dev.headunit.send(JSON.stringify(data));
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Headunit offline. Command undeliverable.' }));
        }
        return;
      }

      if (data.type === 'register_token') {
        if (!data.token || !data.device) return;
        const targetDev = getDevice(data.device);
        targetDev.tokens.add(data.token);
        console.log(`[TOKEN_REGISTERED] Saved token: ${data.token} for device: ${data.device}`);
        ws.send(JSON.stringify({ type: 'token_registered', token: data.token }));
        return;
      }

      if (data.type === 'state') {
        ws.send(JSON.stringify({ type: 'error', message: 'Companions cannot push state directly' }));
        return;
      }
    });

    ws.on('close', () => {
      dev.companions.delete(ws);
      console.log(`[COMPANION] Disconnected — device: ${device}`);
    });

    return;
  }

  // ════════════════════════════════════════
  //  GUEST PAGE
  // ════════════════════════════════════════
  if (role === 'guest') {
    ws._authenticated = false;
    console.log(`[GUEST] Socket connected, awaiting handshake authentication payload...`);

    ws.on('message', (raw) => {
      const data = tryParse(raw);
      if (!data) {
        console.log(`[GUEST_DEBUG] Failed to parse raw message: ${raw.toString()}`);
        return;
      }

      if (data.type === 'guest_auth') {
        const { device: gDevice, token } = data;
        console.log(`[GUEST_AUTH_ATTEMPT] Checking device: "${gDevice}" with token: "${token}"`);

        if (!gDevice || !token) {
          console.log(`[GUEST_DEBUG] Missing parameter. device=${gDevice}, token=${token}`);
          ws.send(JSON.stringify({ type: 'error', message: 'Device and token required' }));
          return ws.close();
        }

        const dev = getDevice(gDevice);
        console.log(`[GUEST_DEBUG] Active valid tokens in server memory for ${gDevice}:`, Array.from(dev.tokens));

        if (!dev.tokens.has(token)) {
          console.log(`[GUEST_AUTH_FAIL] Token matching failed. "${token}" not found in server list.`);
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid Token' }));
          return ws.close();
        }

        ws._authenticated = true;
        ws._device        = gDevice;
        dev.guests.add(ws);
        
        // Temporarily commented out to allow easier debugging and prevent accidental double-loads burning the token
         dev.tokens.delete(token);

        console.log(`[GUEST_SUCCESS] Authenticated successfully — device: ${gDevice}`);
        ws.send(JSON.stringify({ type: 'auth_ok', message: 'Welcome to DriveOS 2.0' }));
        if (dev.lastState) ws.send(JSON.stringify(dev.lastState));
        return;
      }
      ws.send(JSON.stringify({ type: 'error', message: 'Guests cannot send commands' }));
    });

    ws.on('close', () => {
      if (ws._device) getDevice(ws._device).guests.delete(ws);
      console.log(`[GUEST] Socket connection closed.`);
    });
    return;
  }

  return reject(ws, 'Unknown role', `Unknown role: ${role}`);
});

server.listen(PORT, () => {
  console.log(`DriveOS 2.0 Relay running on port ${PORT}`);
});