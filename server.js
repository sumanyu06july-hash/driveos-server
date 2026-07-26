const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;
const GLOBAL_SECRET = 'driveos2secret';
const ADMIN_PIN = '6710'; 

// Central State Dictionaries
const devices = new Map();
const adminClients = new Set();
const blacklist = new Set();
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
            hudState: null,
            hudLastSeen: null,
            companionState: null,
            hud_banned: false,
            companion_banned: false,
            // Anti-Theft & Maintenance State
            parkedGuardActive: false,
            parkedCoords: null
        });
    }
    return devices.get(id);
}

app.use(express.static(path.join(__dirname)));

app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/guest', (req, res) => res.sendFile(path.join(__dirname, 'guest.html')));
app.get('/summary', (req, res) => res.sendFile(path.join(__dirname, 'summary.html')));

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
            
            let hudLatency = 0;
            if (dev.hudState && dev.hudState.latency) {
                hudLatency = parseInt(dev.hudState.latency) || 0;
            } else if (huActive) {
                hudLatency = 35 + Math.floor(Math.random() * 10);
            }

            let compLatency = 0;
            if (dev.companionState && dev.companionState.latency) {
                compLatency = parseInt(dev.companionState.latency) || 0;
            } else if (compActive) {
                compLatency = 40 + Math.floor(Math.random() * 12);
            }

            if (huActive) { absoluteLatencySum += hudLatency; computedCount++; }
            if (compActive) { absoluteLatencySum += compLatency; computedCount++; }

            const tokenList = [];
            if (dev.guestTokens) {
                for (const [tokenKey, meta] of dev.guestTokens.entries()) {
                    tokenList.push({
                        token: tokenKey,
                        type: (typeof meta === 'object' && meta.type) ? meta.type : 'guest'
                    });
                }
            }

            data.push({
                id: deviceId,
                isBlacklisted: blacklist.has(deviceId),
                hud_banned: dev.hud_banned,
                companion_banned: dev.companion_banned,
                parkedGuardActive: dev.parkedGuardActive,
                activeGuests: dev.guests ? dev.guests.size : 0,
                activeSummaryTokens: tokenList,
                hud: {
                    connected: huActive,
                    latency: hudLatency,
                    lastSeen: dev.hudLastSeen,
                    state: dev.hudState || { speed: 0, fuel_percent: 100, odometer: 0, battery_voltage: 12.6 }
                },
                companion: {
                    connected: compActive,
                    latency: compLatency,
                    state: dev.companionState || { battery: 100, signal: "Excellent" }
                }
            });
        }

        const avgLatency = computedCount ? Math.round(absoluteLatencySum / computedCount) : 0;
        const packet = JSON.stringify({ type: 'topology_update', data, metrics: { avgLatency } });

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

    // --- 🔐 ADMIN PIPELINE ---
    if (role === 'admin') {
        const inputAuth = urlParams.get('auth');
        if (inputAuth !== ADMIN_PIN) {
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

                if (command.type === 'burn_access') {
                    const targetDev = devices.get(command.device);
                    if (targetDev) {
                        const tokenMeta = targetDev.guestTokens.get(command.token);
                        const tokenTypeLabel = (tokenMeta && tokenMeta.type === 'summary') ? 'SUMMARY LINK' : 'GUEST PASS';
                        
                        targetDev.guestTokens.delete(command.token);
                        
                        if (targetDev.companion && targetDev.companion.readyState === WebSocket.OPEN) {
                            targetDev.companion.send(JSON.stringify({
                                type: 'token_burned',
                                token: command.token,
                                tokenType: tokenTypeLabel
                            }));
                        }
                    }
                }

                if (command.type === 'toggle_parked_guard') {
                    const targetDev = devices.get(command.device);
                    if (targetDev) {
                        targetDev.parkedGuardActive = command.active;
                        if (command.active && targetDev.hudState) {
                            targetDev.parkedCoords = { lat: targetDev.hudState.lat || 0, lng: targetDev.hudState.lng || 0 };
                        }
                    }
                }

                if (command.type === 'admin_block_device') blacklist.add(command.device);
                if (command.type === 'admin_allow_device') blacklist.delete(command.device);

                if (command.type === 'kill_node') {
                    const targetDev = devices.get(command.device);
                    if (targetDev) {
                        if (command.node === 'hud') {
                            targetDev.hud_banned = true;
                            if (targetDev.headunit) targetDev.headunit.close();
                        }
                        if (command.node === 'companion') {
                            targetDev.companion_banned = true;
                            if (targetDev.companion) targetDev.companion.close();
                        }
                    }
                }

                if (command.type === 'revoke_node_ban') {
                    const targetDev = devices.get(command.device);
                    if (targetDev) {
                        if (command.node === 'hud') targetDev.hud_banned = false;
                        if (command.node === 'companion') targetDev.companion_banned = false;
                    }
                }

                if (command.type === 'admin_panic_purge') {
                    for (const [id, targetDev] of devices.entries()) {
                        if (targetDev.companion && targetDev.companion.readyState === WebSocket.OPEN) {
                            targetDev.companion.send(JSON.stringify({ type: 'purge_request_approved' }));
                        }
                    }
                }
                broadcastTopology();
            } catch (err) {}
        });

        ws.on('close', () => adminClients.delete(ws));
        return;
    }

    // --- HEADUNIT TELEMETRY CORE ---
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

                    // 🚨 LOW FUEL / BATTERY THRESHOLD CHECK
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

                    // 🚨 PARKED GUARD ANTI-THEFT CHECK
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
                }
            } catch (err) {}
        });

        ws.on('close', (code, reason) => {
            if (dev.headunit === ws) {
                dev.headunit = null;
                dev.hudLastSeen = Date.now();
            }
            broadcastTopology();
        });
        return;
    }

    // --- COMPANION CONTROLLER ---
    if (role === 'companion') {
        const secret = urlParams.get('secret');
        if (secret !== GLOBAL_SECRET) return reject(ws, 'SECURITY_VIOLATION', 'Companion key missing.');
        if (dev.companion_banned) return reject(ws, 'NODE_LOCKED', 'Companion suspended.');

        if (dev.companion) { try { dev.companion.close(); } catch(e){} }

        dev.companion = ws;
        console.log(`[COMPANION MOBILE] Remote Deck Sync Synced: ${deviceId}`);
        broadcastTopology();

        ws.on('message', (message) => {
            try {
                const msg = JSON.parse(message);
                interceptTelemetryTransaction(`PHONE_APP(${deviceId.substring(0,4)})`, 'SERVER', msg);

                if (msg.type === 'toggle_parked_guard') {
                    dev.parkedGuardActive = msg.active;
                    broadcastTopology();
                    return;
                }

                if (msg.type === 'request_guest_token') {
                    const guestToken = Math.random().toString(36).substring(2, 10).toUpperCase();
                    const tokenCategory = msg.tokenType || 'guest';
                    dev.guestTokens.set(guestToken, { type: tokenCategory });
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
            } catch (err) {}
        });

        ws.on('close', () => {
            if (dev.companion === ws) dev.companion = null;
            broadcastTopology();
        });
        return;
    }
});

server.listen(PORT, () => console.log(`🟢 DriveOS 2.0 Centralized Hybrid Cluster Network Core Online On: ${PORT}`));