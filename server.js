const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;
const GLOBAL_SECRET = 'driveos2secret';

// State management for devices, live telemetry, and summary handshakes
const devices = new Map();

function getDevice(id) {
    if (!devices.has(id)) {
        devices.set(id, {
            headunit: null,
            companion: null,
            guests: new Set(),
            summaryClients: new Map(), // Active web browsers waiting for a specific token validation
            summaryTokens: new Map(),  // Volatile storage for encrypted owner trip summaries
            guestTokens: new Map(),    // ISOLATED DATA POOL: Dedicated map for passenger live streams
            lastState: null
        });
    }
    return devices.get(id);
}

// Serve the static cyber dashboard layouts
app.get('/guest', (req, res) => {
    res.sendFile(path.join(__dirname, 'guest.html'));
});

app.get('/summary', (req, res) => {
    res.sendFile(path.join(__dirname, 'summary.html'));
});

// Clean rejection pipeline
function reject(ws, type, message) {
    console.warn(`[REJECT] ${type} — ${message}`);
    try {
        ws.send(JSON.stringify({ type: 'error', message }));
        ws.close();
    } catch (e) {
        console.error('[REJECT_ERR] Failed to cleanly disconnect socket:', e.message);
    }
}

// Global WebSocket Logic Layer
wss.on('connection', (ws, req) => {
    const urlParams = new URLSearchParams(req.url.split('?')[1]);
    const role = urlParams.get('role');
    const deviceId = urlParams.get('device') || urlParams.get('deviceId');
    const token = urlParams.get('token');

    if (!role || !deviceId) {
        return reject(ws, 'BAD_HANDSHAKE', 'Missing core routing parameters (role/device).');
    }

    const dev = getDevice(deviceId);

    // ── ROLE BRANCH: WEB SUMMARY CLIENT ─────────────────────────────────────
    if (role === 'summary_client') {
        if (!token) {
            return reject(ws, 'SUMMARY_AUTH_FAIL', 'Summary web client connected without a target token.');
        }

        if (!dev.summaryTokens.has(token)) {
            return reject(ws, 'SUMMARY_EXPIRED', 'The snapshot verification link is invalid or has expired.');
        }

        ws._role = 'summary_client';
        ws._device = deviceId;
        ws._token = token;

        dev.summaryClients.set(token, ws);
        console.log(`[GATEWAY_LOUNGE] Browser client entered holding room for token: ${token}`);

        ws.send(JSON.stringify({ type: 'handshake_ok', status: 'awaiting_companion_approval' }));

        if (dev.companion && dev.companion.readyState === WebSocket.OPEN) {
            console.log(`[GATEWAY_ALERT] Dispatching remote verification alert to Companion phone for token: ${token}`);
            dev.companion.send(JSON.stringify({ type: 'auth_request', token: token }));
        } else {
            console.warn(`[GATEWAY_WARN] Companion app offline. Cannot authorize summary access for token: ${token}`);
        }

        ws.on('close', () => {
            if (dev.summaryClients.get(token) === ws) {
                dev.summaryClients.delete(token);
                console.log(`[GATEWAY_LOUNGE] Browser disconnected from holding lounge for token: ${token}`);
            }
        });
        return;
    }

    // ── ROLE BRANCH: HEADUNIT TABLET ────────────────────────────────────────
    if (role === 'headunit') {
        const secret = urlParams.get('secret');
        if (secret !== GLOBAL_SECRET) {
            return reject(ws, 'SECURITY_VIOLATION', 'Invalid global infrastructure handshake key.');
        }

        if (dev.headunit) {
            console.log(`[CONFLICT] Ghost headunit detected for device=${deviceId}. Terminating old instance...`);
            dev.headunit.send(JSON.stringify({ type: 'error', message: 'Newer connection instance took over.' }));
            dev.headunit.close();
        }

        dev.headunit = ws;
        ws._device = deviceId;
        console.log(`[HEADUNIT] Connected — device: ${deviceId}`);

        ws.on('message', (message) => {
            try {
                const msg = JSON.parse(message);

                if (msg.type === 'register_summary_token') {
                    const targetToken = msg.token;
                    const encryptedData = msg.data;

                    if (!targetToken || !encryptedData) return;

                    dev.summaryTokens.set(targetToken, encryptedData);
                    console.log(`[SUMMARY_REGISTERED] Cached encrypted trip summary layout data against token: ${targetToken}`);
                    return;
                }

                if (msg.type === 'state') {
                    dev.lastState = msg;
                    dev.guests.forEach(guest => {
                        if (guest.readyState === WebSocket.OPEN) {
                            guest.send(JSON.stringify(msg));
                        }
                    });
                }
            } catch (err) {
                console.error('[HEADUNIT_MSG_ERR] Error parsing frame payload data:', err.message);
            }
        });

        ws.on('close', () => {
            if (dev.headunit === ws) dev.headunit = null;
            console.log(`[HEADUNIT] Device connection dropped for identity: ${deviceId}`);
        });
        return;
    }

    // ── ROLE BRANCH: COMPANION APP PHONE ────────────────────────────────────
    if (role === 'companion') {
        const secret = urlParams.get('secret');
        if (secret !== GLOBAL_SECRET) {
            return reject(ws, 'SECURITY_VIOLATION', 'Invalid global infrastructure companion access authorization.');
        }

        if (dev.companion) {
            console.log(`[CONFLICT] Ghost companion detected for device=${deviceId}. Swapping routing sockets...`);
            dev.companion.close();
        }

        dev.companion = ws;
        ws._device = deviceId;
        console.log(`[COMPANION] Connected — remote device handler: ${deviceId}`);

        ws.on('message', (message) => {
            try {
                const msg = JSON.parse(message);

                // INTERCEPT LOCAL GUEST PASSENGER QR REQUESTS
                if (msg.type === 'request_guest_token') {
                    const guestToken = Math.random().toString(36).substring(2, 18);
                    
                    dev.guestTokens.set(guestToken, true);
                    console.log(`[GUEST_TOKEN_GEN] Isolated passenger stream route token compiled: ${guestToken}`);
                    
                    ws.send(JSON.stringify({
                        type: 'token_registered',
                        token: guestToken
                    }));
                    return;
                }

                // HANDLE SECURE GATEWAY VERIFICATION VALIDATION FROM OWNER PHONE (APPROVE)
                if (msg.type === 'approve_summary_access') {
                    const targetToken = msg.token;
                    console.log(`[GATEWAY_SIGNAL] Companion explicitly APPROVED web browser access request for token: ${targetToken}`);

                    const browserClient = dev.summaryClients.get(targetToken);
                    const cachedDataString = dev.summaryTokens.get(targetToken);

                    if (browserClient && cachedDataString && browserClient.readyState === WebSocket.OPEN) {
                        browserClient.send(JSON.stringify({
                            type: 'summary_payload',
                            data: cachedDataString
                        }));
                        console.log(`[GATEWAY_RELEASE] Dispatched secure ciphertext payload out to target client screen. Scheduling delayed Burn Rule.`);
                    } else {
                        console.warn(`[GATEWAY_FAIL] Target client layout matching token ${targetToken} dropped or went missing.`);
                    }

                    setTimeout(() => {
                        try {
                            if (browserClient && browserClient.readyState === WebSocket.OPEN) {
                                browserClient.close();
                            }
                        } catch (closeErr) {
                            console.error('[GATEWAY_CLOSE_ERR] Error execution close loop:', closeErr.message);
                        }
                        dev.summaryTokens.delete(targetToken);
                        dev.summaryClients.delete(targetToken);
                        console.log(`[GATEWAY_BURN] Volatile summary token ${targetToken} permanently purged from memory maps via delayed Burn Rule.`);
                    }, 500);
                    return; 
                }

                // HANDLE SECURE GATEWAY VERIFICATION VALIDATION FROM OWNER PHONE (DENY)
                if (msg.type === 'deny_summary_access') {
                    const targetToken = msg.token;
                    console.log(`[GATEWAY_SIGNAL] Companion explicitly DENIED web browser access request for token: ${targetToken}`);

                    const browserClient = dev.summaryClients.get(targetToken);

                    if (browserClient && browserClient.readyState === WebSocket.OPEN) {
                        browserClient.send(JSON.stringify({
                            type: 'error',
                            message: 'ACCESS_DENIED_BY_OWNER'
                        }));
                        console.log(`[GATEWAY_KICK] Notified browser client of denial configuration context.`);
                    }

                    dev.summaryTokens.delete(targetToken);
                    dev.summaryClients.delete(targetToken);
                    console.log(`[GATEWAY_BURN] Volatile summary token ${targetToken} permanently purged from memory maps.`);
                    return;
                }

                // Only forward non-auth actions down to tablet layout line
                if (dev.headunit && dev.headunit.readyState === WebSocket.OPEN) {
                    dev.headunit.send(JSON.stringify(msg));
                }
            } catch (err) {
                console.error('[COMPANION_MSG_ERR] Error extracting companion control frame array:', err.message);
            }
        });

        ws.on('close', () => {
            if (dev.companion === ws) dev.companion = null;
            console.log(`[COMPANION] Controller phone layer detached for: ${deviceId}`);
        });
        return;
    }

    // ── ROLE BRANCH: PASSENGER LIVE GUEST LAYOUT ─────────────────────────────
    if (role === 'guest') {
        ws._authenticated = false;
        ws._device = deviceId;

        ws.on('message', (message) => {
            try {
                const msg = JSON.parse(message);
                if (msg.type === 'guest_auth') {
                    const targetToken = msg.token;
                    
                    if (dev.guestTokens.has(targetToken)) {
                        ws._authenticated = true;
                        dev.guests.add(ws);
                        console.log(`[GUEST_SUCCESS] Passenger successfully authenticated via isolated token mapping layout.`);
                        ws.send(JSON.stringify({ type: 'auth_ok', message: 'Welcome to DriveOS 2.0 Live Passenger Stream' }));
                        if (dev.lastState) ws.send(JSON.stringify(dev.lastState));
                        return;
                    }
                    return reject(ws, 'AUTH_FAILED', 'Invalid passenger validation keys.');
                }
                ws.send(JSON.stringify({ type: 'error', message: 'Guests cannot broadcast functional control commands.' }));
            } catch (err) {
                return reject(ws, 'PARSE_ERROR', 'Malformed data frame mapping properties array.');
            }
        });

        ws.on('close', () => {
            dev.guests.delete(ws);
            console.log(`[GUEST] Socket connection closed cleanly.`);
        });
        return;
    }

    return reject(ws, 'UNKNOWN_ROLE', `Passed system identifier string role variant is unmapped: ${role}`);
});

server.listen(PORT, () => {
    console.log(`DriveOS 2.0 Central Hybrid Relay running on configuration port ${PORT}`);
});