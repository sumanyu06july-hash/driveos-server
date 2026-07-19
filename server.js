const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;
const GLOBAL_SECRET = 'driveos2secret';
const ADMIN_PIN = '6710'; // Master administrative passcode configuration string

// Global Volatile State Registers
const devices = new Map();
const adminClients = new Set();
const blacklist = new Set(); // Stores banned hardware cluster identities dynamically
let globalLogSequence = 1;

function getDevice(id) {
    if (!devices.has(id)) {
        devices.set(id, {
            headunit: null,
            companion: null,
            guests: new Set(),
            summaryClients: new Map(),
            summaryTokens: new Map(),
            guestTokens: new Map(),
            lastState: null
        });
    }
    return devices.get(id);
}

// Static Assets Routing Layer
app.use(express.static(path.join(__dirname)));

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/guest', (req, res) => {
    res.sendFile(path.join(__dirname, 'guest.html'));
});

app.get('/summary', (req, res) => {
    res.sendFile(path.join(__dirname, 'summary.html'));
});

function reject(ws, type, message) {
    console.warn(`[REJECT] ${type} — ${message}`);
    try {
        ws.send(JSON.stringify({ type: 'error', message }));
        ws.close();
    } catch (e) {
        console.error('[REJECT_ERR] Failed to cleanly sever socket matrix:', e.message);
    }
}

// Broadcast Active Network Layout Metrics to Admin Panels
function broadcastTopology() {
    const data = [];
    let absoluteLatencySum = 0;
    let computedCount = 0;

    for (const [deviceId, dev] of devices.entries()) {
        const huActive = !!dev.headunit && dev.headunit.readyState === WebSocket.OPEN;
        const compActive = !!dev.companion && dev.companion.readyState === WebSocket.OPEN;
        
        // Compute running latency markers dynamically from state payload arrays if active
        let nodeLatency = 0;
        if (dev.lastState && dev.lastState.latency) {
            nodeLatency = parseInt(dev.lastState.latency) || 0;
        } else if (huActive) {
            nodeLatency = 35 + Math.floor(Math.random() * 15); // Dynamic mock base delta for runtime tracking
        }

        if (huActive || compActive) {
            absoluteLatencySum += nodeLatency;
            computedCount++;
        }

        data.push({
            id: deviceId,
            name: dev.lastState && dev.lastState.deviceName ? dev.lastState.deviceName : `Cluster Profile: ${deviceId.toUpperCase()}`,
            headunitConnected: huActive,
            companionConnected: compActive,
            activeGuests: Array.from(dev.guests).filter(g => g.readyState === WebSocket.OPEN).length,
            activeSummaryTokens: Array.from(dev.summaryTokens.keys()),
            isBlacklisted: blacklist.has(deviceId),
            latency: nodeLatency,
            lastSeen: huActive || compActive ? "now" : "offline"
        });
    }

    const avgLatency = computedCount ? Math.round(absoluteLatencySum / computedCount) : 0;
    const packet = JSON.stringify({ 
        type: 'topology_update', 
        data,
        metrics: { avgLatency }
    });

    adminClients.forEach(admin => {
        if (admin.readyState === WebSocket.OPEN) admin.send(packet);
    });
}

// Telemetry Stream Wiretap Interceptor Hook
function interceptTelemetryTransaction(origin, target, payload) {
    const sequenceId = String(globalLogSequence++).padStart(4, '0');
    const packet = JSON.stringify({
        type: 'wiretap_intercept',
        sequence: sequenceId,
        origin,
        target,
        payload
    });

    adminClients.forEach(admin => {
        if (admin.readyState === WebSocket.OPEN) admin.send(packet);
    });
}

wss.on('connection', (ws, req) => {
    const urlParams = new URLSearchParams(req.url.split('?')[1]);
    const role = urlParams.get('role');
    const deviceId = urlParams.get('device') || urlParams.get('deviceId');
    const token = urlParams.get('token');

    if (!role) {
        return reject(ws, 'BAD_HANDSHAKE', 'Missing system configuration role parameters.');
    }

    // --- 🔐 ADMINISTRATIVE CONTROLS INTERCEPT LOOP ---
    if (role === 'admin') {
        const inputAuth = urlParams.get('auth');
        if (inputAuth !== ADMIN_PIN) {
            // Send clear structural message parameter packet to unlock overlay before disconnecting lines
            ws.send(JSON.stringify({ type: 'auth_error', message: 'INCORRECT_PIN_REJECTED' }));
            setTimeout(() => { try { ws.close(); } catch(e){} }, 200);
            return;
        }

        adminClients.add(ws);
        console.log('[ADMIN] Secure overlay panel loaded and attached to core mapping array.');
        
        ws.send(JSON.stringify({ type: 'handshake_ok', message: 'Core admin terminal gateway open.' }));
        broadcastTopology();

        ws.on('message', (message) => {
            try {
                const command = JSON.parse(message);

                if (command.type === 'burn_access') {
                    const dev = devices.get(command.device);
                    if (dev) {
                        const browserClient = dev.summaryClients.get(command.token);
                        if (browserClient && browserClient.readyState === WebSocket.OPEN) {
                            // Target demotion placeholder trigger deployment
                            browserClient.send(JSON.stringify({ type: 'demote_to_placeholder' }));
                            setTimeout(() => browserClient.close(), 100);
                        }
                        dev.summaryTokens.delete(command.token);
                        dev.summaryClients.delete(command.token);
                        dev.guestTokens.delete(command.token);
                        console.log(`[BURNT ACCESS] Terminated active token register: ${command.token}`);
                    }
                }

                if (command.type === 'admin_block_device') {
                    blacklist.add(command.device);
                    const dev = devices.get(command.device);
                    if (dev) {
                        if (dev.headunit) dev.headunit.close();
                        if (dev.companion) dev.companion.close();
                        dev.guests.forEach(g => g.close());
                    }
                    console.log(`[FIREWALL MATRIX] Injected runtime blacklist ban for target profile: ${command.device}`);
                }

                if (command.type === 'admin_allow_device') {
                    blacklist.delete(command.device);
                    console.log(`[FIREWALL MATRIX] Revoked active tracking ban for target profile: ${command.device}`);
                }

                if (command.type === 'admin_panic_purge') {
                    console.log('[🚨 INFRASTRUCTURE EMERGENCY PURGE ACTIVATED] Flashing core variables...');
                    for (const [id, dev] of devices.entries()) {
                        if (dev.headunit) dev.headunit.close();
                        if (dev.companion) dev.companion.close();
                        dev.guests.forEach(g => g.close());
                        dev.summaryClients.forEach(s => s.close());
                    }
                    devices.clear();
                    blacklist.clear();
                }

                broadcastTopology();
            } catch (err) {
                console.error('[ADMIN_CMD_ERR] Failed processing inbound override packet array:', err.message);
            }
        });

        ws.on('close', () => {
            adminClients.delete(ws);
            console.log('[ADMIN] Command dashboard instance detached.');
        });
        return;
    }

    // --- 🛡️ FIREWALL BLACKLIST SHIELD ENFORCER ---
    if (deviceId && blacklist.has(deviceId)) {
        return reject(ws, 'AUTHENTICATION_REVOKED', 'This cluster terminal identity profile has been permanently blacklisted.');
    }

    if (!deviceId) {
        return reject(ws, 'BAD_HANDSHAKE', 'Missing unique parameter cluster node reference.');
    }

    const dev = getDevice(deviceId);

    // --- SUMMARY WEB CLIENT LOUNGE ---
    if (role === 'summary_client') {
        if (!token) return reject(ws, 'SUMMARY_AUTH_FAIL', 'Missing verification token references.');
        if (!dev.summaryTokens.has(token)) return reject(ws, 'SUMMARY_EXPIRED', 'Token index mismatch or link expired.');

        ws._role = 'summary_client';
        ws._device = deviceId;
        ws._token = token;

        dev.summaryClients.set(token, ws);
        ws.send(JSON.stringify({ type: 'handshake_ok', status: 'awaiting_companion_approval' }));

        if (dev.companion && dev.companion.readyState === WebSocket.OPEN) {
            dev.companion.send(JSON.stringify({ type: 'auth_request', token: token }));
        }
        
        broadcastTopology();

        ws.on('close', () => {
            if (dev.summaryClients.get(token) === ws) dev.summaryClients.delete(token);
            broadcastTopology();
        });
        return;
    }

    // --- AUTOMOTIVE HEADUNIT HUD CLIENT ---
    if (role === 'headunit') {
        const secret = urlParams.get('secret');
        if (secret !== GLOBAL_SECRET) return reject(ws, 'SECURITY_VIOLATION', 'Handshake token validation error.');

        if (dev.headunit) {
            dev.headunit.send(JSON.stringify({ type: 'error', message: 'Concurrent takeover instance running.' }));
            dev.headunit.close();
        }

        dev.headunit = ws;
        ws._device = deviceId;
        console.log(`[HEADUNIT CORE] Registered target cluster link: ${deviceId}`);
        broadcastTopology();

        ws.on('message', (message) => {
            try {
                const msg = JSON.parse(message);
                
                interceptTelemetryTransaction(`HUD_UNIT(${deviceId.substring(0,6)})`, 'RELAY_GATEWAY', msg);

                if (msg.type === 'register_summary_token') {
                    dev.summaryTokens.set(msg.token, msg.data);
                    broadcastTopology();
                    return;
                }

                if (msg.type === 'state') {
                    dev.lastState = msg;
                    dev.guests.forEach(guest => {
                        if (guest.readyState === WebSocket.OPEN) guest.send(JSON.stringify(msg));
                    });
                }
            } catch (err) {}
        });

        ws.on('close', () => {
            if (dev.headunit === ws) dev.headunit = null;
            console.log(`[HEADUNIT CORE] Dropped link connection state: ${deviceId}`);
            broadcastTopology();
        });
        return;
    }

    // --- REMOTE COMPANION MOBILE HANDLER ---
    if (role === 'companion') {
        const secret = urlParams.get('secret');
        if (secret !== GLOBAL_SECRET) return reject(ws, 'SECURITY_VIOLATION', 'Companion channel setup parameters missing.');

        if (dev.companion) dev.companion.close();

        dev.companion = ws;
        ws._device = deviceId;
        console.log(`[COMPANION PHONE] Connected configuration reference: ${deviceId}`);
        broadcastTopology();

        ws.on('message', (message) => {
            try {
                const msg = JSON.parse(message);
                
                interceptTelemetryTransaction(`PHONE_APP(${deviceId.substring(0,6)})`, 'RELAY_GATEWAY', msg);

                if (msg.type === 'request_guest_token') {
                    const guestToken = Math.random().toString(36).substring(2, 18);
                    dev.guestTokens.set(guestToken, true);
                    ws.send(JSON.stringify({ type: 'token_registered', token: guestToken }));
                    return;
                }

                if (msg.type === 'approve_summary_access') {
                    const browserClient = dev.summaryClients.get(msg.token);
                    const cachedDataString = dev.summaryTokens.get(msg.token);

                    if (browserClient && cachedDataString && browserClient.readyState === WebSocket.OPEN) {
                        browserClient.send(JSON.stringify({ type: 'summary_payload', data: cachedDataString }));
                    }

                    setTimeout(() => {
                        try { if (browserClient) browserClient.close(); } catch (e) {}
                        dev.summaryTokens.delete(msg.token);
                        dev.summaryClients.delete(msg.token);
                        broadcastTopology();
                    }, 1500);
                    return; 
                }

                if (msg.type === 'deny_summary_access') {
                    const browserClient = dev.summaryClients.get(msg.token);
                    if (browserClient && browserClient.readyState === WebSocket.OPEN) {
                        browserClient.send(JSON.stringify({ type: 'error', message: 'ACCESS_DENIED_BY_OWNER' }));
                    }
                    dev.summaryTokens.delete(msg.token);
                    dev.summaryClients.delete(msg.token);
                    broadcastTopology();
                    return;
                }

                if (dev.headunit && dev.headunit.readyState === WebSocket.OPEN) {
                    dev.headunit.send(JSON.stringify(msg));
                    interceptTelemetryTransaction('RELAY_GATEWAY', `HUD_UNIT(${deviceId.substring(0,6)})`, msg);
                }
            } catch (err) {}
        });

        ws.on('close', () => {
            if (dev.companion === ws) dev.companion = null;
            console.log(`[COMPANION PHONE] Connection severed mapping index: ${deviceId}`);
            broadcastTopology();
        });
        return;
    }

    // --- PASSENGER STREAM NEST CHANNELS ---
    if (role === 'guest') {
        ws._authenticated = false;
        ws._device = deviceId;

        ws.on('message', (message) => {
            try {
                const msg = JSON.parse(message);
                if (msg.type === 'guest_auth') {
                    if (dev.guestTokens.has(msg.token)) {
                        ws._authenticated = true;
                        dev.guests.add(ws);
                        ws.send(JSON.stringify({ type: 'auth_ok', message: 'Passenger stream synced.' }));
                        if (dev.lastState) ws.send(JSON.stringify(dev.lastState));
                        broadcastTopology();
                        return;
                    }
                    return reject(ws, 'AUTH_FAILED', 'Passenger entry token evaluation mapping parameter error.');
                }
            } catch (err) {
                return reject(ws, 'PARSE_ERROR', 'Malformed initialization array strings.');
            }
        });

        ws.on('close', () => {
            dev.guests.delete(ws);
            broadcastTopology();
        });
        return;
    }

    return reject(ws, 'UNKNOWN_ROLE', 'Passed identification context route missing.');
});

server.listen(PORT, () => {
    console.log(`\n=============================================================`);
    console.log(`🟢 DriveOS 2.0 Centralized Hybrid Cluster Network Core Online`);
    console.log(`📡 Cloud Deployment Port Bindings Active Processing On: ${PORT}`);
    console.log(`=============================================================\n`);
});