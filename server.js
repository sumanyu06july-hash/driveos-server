// ═══════════════════════════════════════════════
//  DriveOS 2.0 — Relay Server
//  Handles: WebSocket relay + /guest HTTP route
// ═══════════════════════════════════════════════

const express   = require('express');
const http      = require('http');
const WebSocket = require('ws');
const path      = require('path');

// ── CONFIG ──────────────────────────────────────
const GLOBAL_SECRET = process.env.DRIVEOS_SECRET || 'driveos2secret';
const PORT          = process.env.PORT || 3000;

// ── STATE ───────────────────────────────────────
// devices['myaura001'] = {
//   headunit:  <WebSocket>,
//   guests:    Set<WebSocket>,
//   tokens:    Set<string>,
//   lastState: {}
// }
const devices = {};

function getDevice(deviceId) {
  if (!devices[deviceId]) {
    devices[deviceId] = {
      headunit:  null,
      guests:    new Set(),
      tokens:    new Set(),
      lastState: null
    };
  }
  return devices[deviceId];
}

// ── EXPRESS ─────────────────────────────────────
const app    = express();
const server = http.createServer(app);

app.get('/guest', (req, res) => {
  res.sendFile(path.join(__dirname, 'guest.html'));
});

app.get('/', (req, res) => {
  res.send('DriveOS 2.0 Relay — Online');
});

// ── WEBSOCKET ────────────────────────────────────
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
  const url    = new URL(req.url, 'http://localhost');
  const role   = url.searchParams.get('role');
  const device = url.searchParams.get('device');
  const secret = url.searchParams.get('secret');

  // ════════════════════════════════
  //  HEADUNIT
  //  URL: wss://...?role=headunit&device=myaura001&secret=driveos2secret
  // ════════════════════════════════
  if (role === 'headunit') {

    if (secret !== GLOBAL_SECRET) {
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid secret' }));
      ws.close();
      console.log(`[HEADUNIT] Rejected — bad secret. Device: ${device}`);
      return;
    }

    if (!device) {
      ws.send(JSON.stringify({ type: 'error', message: 'Device ID required' }));
      ws.close();
      return;
    }

    const dev    = getDevice(device);
    dev.headunit = ws;
    console.log(`[HEADUNIT] Connected — device: ${device}`);
    ws.send(JSON.stringify({ type: 'headunit_auth_ok', message: 'Relay active' }));

    ws.on('message', (raw) => {
      let data;
      try { data = JSON.parse(raw); } catch { return; }

      // Broadcast state to all authenticated guests
      if (data.type === 'state') {
        dev.lastState = data;
        const payload = JSON.stringify(data);
        dev.guests.forEach(guest => {
          if (guest.readyState === WebSocket.OPEN) {
            guest.send(payload);
          }
        });
      }
    });

    ws.on('close', () => {
      dev.headunit = null;
      console.log(`[HEADUNIT] Disconnected — device: ${device}`);
      dev.guests.forEach(guest => {
        if (guest.readyState === WebSocket.OPEN) {
          guest.send(JSON.stringify({
            type: 'error',
            message: 'Headunit disconnected'
          }));
        }
      });
    });

    ws.on('error', (err) => {
      console.error(`[HEADUNIT] Error — device: ${device}:`, err.message);
    });

    return;
  }

  // ════════════════════════════════
  //  COMPANION APP
  //  URL: wss://...?role=companion&device=myaura001&secret=driveos2secret
  // ════════════════════════════════
  if (role === 'companion') {

    if (secret !== GLOBAL_SECRET) {
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid secret' }));
      ws.close();
      console.log(`[COMPANION] Rejected — bad secret. Device: ${device}`);
      return;
    }

    if (!device) {
      ws.send(JSON.stringify({ type: 'error', message: 'Device ID required' }));
      ws.close();
      return;
    }

    console.log(`[COMPANION] Connected — device: ${device}`);
    ws.send(JSON.stringify({ type: 'companion_auth_ok', message: 'Companion connected' }));

    ws.on('message', (raw) => {
      let data;
      try { data = JSON.parse(raw); } catch { return; }

      // ── TOKEN REGISTRATION ──
      // Companion sends: {"type":"register_token","token":"a3f9b2c1","device":"myaura001"}
      if (data.type === 'register_token') {
        if (!data.token || !data.device) {
          ws.send(JSON.stringify({ type: 'error', message: 'Token and device required' }));
          return;
        }
        const dev = getDevice(data.device);
        dev.tokens.add(data.token);
        console.log(`[TOKEN] Registered — token: ${data.token} | device: ${data.device}`);
        ws.send(JSON.stringify({ type: 'token_registered', token: data.token }));
        return;
      }
    });

    ws.on('close', () => {
      console.log(`[COMPANION] Disconnected — device: ${device}`);
    });

    ws.on('error', (err) => {
      console.error(`[COMPANION] Error:`, err.message);
    });

    return;
  }

  // ════════════════════════════════
  //  GUEST PAGE
  //  URL: wss://...?role=guest
  //  Auth via JSON handshake after connect
  // ════════════════════════════════
  if (role === 'guest') {

    console.log(`[GUEST] Connected — awaiting auth`);
    ws._authenticated = false;

    ws.on('message', (raw) => {
      let data;
      try { data = JSON.parse(raw); } catch { return; }

      // ── GUEST AUTH HANDSHAKE ──
      // Guest sends: {"type":"guest_auth","device":"myaura001","token":"a3f9b2c1"}
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
        dev.tokens.delete(token); // one-time use — token is burned after use

        console.log(`[GUEST] Authenticated — device: ${gDevice}`);
        ws.send(JSON.stringify({ type: 'auth_ok', message: 'Welcome to DriveOS 2.0' }));

        // Send last known state immediately so page isn't blank
        if (dev.lastState) {
          ws.send(JSON.stringify(dev.lastState));
        }

        return;
      }

      // Block unauthenticated messages
      if (!ws._authenticated) {
        ws.send(JSON.stringify({ type: 'error', message: 'Not authenticated' }));
        ws.close();
      }
    });

    ws.on('close', () => {
      if (ws._device) {
        getDevice(ws._device).guests.delete(ws);
        console.log(`[GUEST] Disconnected — device: ${ws._device}`);
      }
    });

    ws.on('error', (err) => {
      console.error(`[GUEST] Error:`, err.message);
    });

    return;
  }

  // Unknown role
  ws.send(JSON.stringify({ type: 'error', message: 'Unknown role' }));
  ws.close();
  console.log(`[CONNECTION] Rejected — unknown role: ${role}`);
});

// ── START ────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`DriveOS 2.0 Relay running on port ${PORT}`);
});