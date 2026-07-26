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
            guestTokens: new Map(), // Stores token string -> { type: 'guest' | 'summary' }
            hudState: null,
            companionState: null,
            hud_banned: false,
            companion_banned: false
        });
    }
    return devices.get(id);
}

// Serve Static App Framework Roots
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
        console.error('[REJECT_ERR] Failed to cleanly sever connection matrix:', e.message);
    }
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

            // Map token details including explicit type metadata
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
                activeGuests: dev.guests ? dev.guests.size : 0,
                activeSummaryTokens: tokenList,
                hud: {
                    connected: huActive,
                    latency: hudLatency,
                    state: dev.hudState || { speed: 0, fuel_percent: 100, odometer: 0 }
                },
                companion: {
                    connected: compActive,
                    latency: compLatency,
                    state: dev.companionState || { battery: 100, signal: "Excellent" }
                }
            });
        }

        const avgLatency = computedCount ? Math.round(absoluteLatencySum / computedCount) : 0;
        const packet = JSON.stringify({ 
            type: 'topology_update', 
            data, 
            metrics: { avgLatency } 
        });

        adminClients.forEach(admin => { 
            if (admin.readyState === WebSocket.OPEN) {
                admin.send(packet); 
            }
        });
    } catch (err) {
        console.error('[CRITICAL TOPO ERROR]: broadcastTopology crashed internally:', err.message);
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

    let rawDevice = urlParams.get('deviceId') || urlParams.get('device');
    if (!rawDevice || rawDevice === 'null' || rawDevice === 'undefined') {
        rawDevice = 'myaura001'; 
    }
    const deviceId = rawDevice.trim();

    if (!role) {
        return reject(ws, 'BAD_HANDSHAKE', 'Missing system configuration role identifier parameters.');
    }

    // --- 🔐 ADMINISTRATIVE CONTROLS PIPELINE ---
    if (role === 'admin') {
        const inputAuth = urlParams.get('auth');
        if (inputAuth !== ADMIN_PIN) {
            ws.send(JSON.stringify({ type: 'auth_error' }));
            setTimeout(() => { try{ws.close();}catch(e){} }, 200);
            return;
        }
        adminClients.add(ws);
        ws.send(JSON.stringify({ type: 'handshake_ok', message: 'Ecosystem dashboard control bridge authenticated.' }));
        broadcastTopology();

        ws.on('message', (message) => {
            try {
                const command = JSON.parse(message);

                if (command.type === 'admin_purge_response') {
                    for (const [id, dev] of devices.entries()) {
                        if (dev.companion && dev.companion.readyState === WebSocket.OPEN) {
                            if (command.decision === 'approve') {
                                dev.companion.send(JSON.stringify({ type: 'purge_request_approved' }));
                            } else {
                                dev.companion.send(JSON.stringify({ type: 'purge_request_denied', overrideCode: '000000202688' }));
                                setTimeout(() => { try{dev.companion.close();}catch(e){} }, 500);
                            }
                        }
                    }
                }
                
                if (command.type === 'burn_access') {
                    const dev = devices.get(command.device);
                    if (dev) {
                        const tokenMeta = dev.guestTokens.get(command.token);
                        const tokenTypeLabel = (tokenMeta && tokenMeta.type === 'summary') ? 'SUMMARY LINK' : 'GUEST PASS';
                        
                        dev.guestTokens.delete(command.token);
                        console.log(`[ADMIN ACTION] Access token permanently burned: ${command.token}`);

                        // Log to wiretap intercept console
                        interceptTelemetryTransaction('ADMIN_PANEL', `PHONE_APP(${command.device.substring(0,4)})`, {
                            action: 'TOKEN_BURNED',
                            token: command.token,
                            type: tokenTypeLabel
                        });

                        // 📲 NOTIFY COMPANION PHONE OF BURN EVENT
                        if (dev.companion && dev.companion.readyState === WebSocket.OPEN) {
                            dev.companion.send(JSON.stringify({
                                type: 'token_burned',
                                token: command.token,
                                tokenType: tokenTypeLabel,
                                message: `Authorization token [${command.token}] (${tokenTypeLabel}) has been burned from Overlord Control Center.`
                            }));
                        }
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
                }

                if (command.type === 'admin_allow_device') {
                    blacklist.delete(command.device);
                }

                if (command.type === 'kill_node') {
                    const dev = devices.get(command.device);
                    if (dev) {
                        if (command.node === 'hud') {
                            dev.hud_banned = true;
                            if (dev.headunit) dev.headunit.close();
                        }
                        if (command.node === 'companion') {
                            dev.companion_banned = true;
                            if (dev.companion) dev.companion.close();
                        }
                    }
                }

                if (command.type === 'revoke_node_ban') {
                    const dev = devices.get(command.device);
                    if (dev) {
                        if (command.node === 'hud') dev.hud_banned = false;
                        if (command.node === 'companion') dev.companion_banned = false;
                    }
                }

                if (command.type === 'admin_panic_purge') {
                    for (const [id, dev] of devices.entries()) {
                        if (dev.companion && dev.companion.readyState === WebSocket.OPEN) {
                            dev.companion.send(JSON.stringify({ type: 'purge_request_approved' }));
                        }
                    }
                    ws.send(JSON.stringify({ type: 'wiretap_intercept', payload: { message: "Purge initialization frame sent to companion app." } }));
                }
                broadcastTopology();
            } catch (err) {
                console.error('[ADMIN_COMMAND_ERR] Malformed payload package packet:', err.message);
            }
        });

        ws.on('close', () => { adminClients.delete(ws); });
        return;
    }

    // --- 🛡️ FIREWALL SHIELD GATEKEEPER ---
    if (deviceId && blacklist.has(deviceId)) {
        return reject(ws, 'AUTHENTICATION_REVOKED', 'This hardware profile has been blacklisted.');
    }

    const dev = getDevice(deviceId);

    // --- SUMMARY WEB RECEIVER MODULE ---
    if (role === 'summary_client') {
        if (!token) return reject(ws, 'SUMMARY_AUTH_FAIL', 'Missing allocation verification vectors.');
        if (!dev.guestTokens.has(token)) return reject(ws, 'SUMMARY_EXPIRED', 'Token index mismatch or link reference expired.');

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

    // --- HEADUNIT TELEMETRY CORE ENGINE ---
    if (role === 'headunit') {
        const secret = urlParams.get('secret');
        if (secret !== GLOBAL_SECRET) return reject(ws, 'SECURITY_VIOLATION', 'Handshake access token variable value invalid.');

        if (dev.hud_banned) {
            return reject(ws, 'NODE_LOCKED', 'Headunit authorization explicitly suspended by administrative panel.');
        }

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
                
                if (msg && msg.type === 'ping') {
                    return; 
                }

                interceptTelemetryTransaction(`HUD_UNIT(${deviceId.substring(0,4)})`, 'SERVER', msg);

                if (msg.type === 'state') {
                    dev.hudState = msg;
                    dev.guests.forEach(guest => {
                        if (guest.readyState === WebSocket.OPEN) guest.send(JSON.stringify(msg));
                    });
                    broadcastTopology();
                }
            } catch (err) {}
        });

        ws.on('close', (code, reason) => {
            const cleanReason = reason ? reason.toString() : "None";
            console.warn(`[🚨 HUD DISCONNECT] Device: ${deviceId} | Code: ${code} | Reason: ${cleanReason}`);
            
            if (dev.headunit === ws) dev.headunit = null;
            broadcastTopology();
        });
        return;
    }

    // --- COMPANION CONTROLLER DEVICE MATRIX ---
    if (role === 'companion') {
        const secret = urlParams.get('secret');
        if (secret !== GLOBAL_SECRET) return reject(ws, 'SECURITY_VIOLATION', 'Companion config key missing.');

        if (dev.companion_banned) {
            return reject(ws, 'NODE_LOCKED', 'Companion mobile terminal link suspended by administrative panel.');
        }

        if (dev.companion) { try { dev.companion.close(); } catch(e){} }

        dev.companion = ws;
        console.log(`[COMPANION MOBILE] Remote Deck Sync Node Synced: ${deviceId}`);
        broadcastTopology();

        ws.on('message', (message) => {
            try {
                const msg = JSON.parse(message);
                interceptTelemetryTransaction(`PHONE_APP(${deviceId.substring(0,4)})`, 'SERVER', msg);
                
                if (msg.type === 'companion_purge_request') {
                    adminClients.forEach(admin => {
                        if (admin.readyState === WebSocket.OPEN) {
                            admin.send(JSON.stringify({ 
                                type: 'purge_handshake_challenge', 
                                deviceId: deviceId 
                            }));
                        }
                    });
                    return;
                }

                if (msg.type === 'companion_purge_confirmed') {
                    console.log('[🚨 CRITICAL SYSTEM PANIC EXECUTED VIA VERIFIED PHONE SIGNATURE]');
                    for (const [id, targetDev] of devices.entries()) {
                        if (targetDev.headunit) targetDev.headunit.close();
                        if (targetDev.companion && targetDev.companion !== ws) targetDev.companion.close();
                        targetDev.guests.forEach(g => g.close());
                        targetDev.summaryClients.forEach(s => s.close());
                    }
                    devices.clear();
                    blacklist.clear();
                    
                    devices.set(deviceId, dev);
                    
                    adminClients.forEach(admin => {
                        if (admin.readyState === WebSocket.OPEN) {
                            admin.send(JSON.stringify({ type: 'purge_success' }));
                        }
                    });
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

                if (msg.type === 'approve_summary_access') {
                    const browserClient = dev.summaryClients.get(msg.token);
                    if (browserClient && browserClient.readyState === WebSocket.OPEN) {
                        browserClient.send(JSON.stringify({ type: 'summary_payload', data: dev.hudState }));
                    }
                    setTimeout(() => {
                        try { if (browserClient) browserClient.close(); } catch (e) {}
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
                    dev.summaryClients.delete(msg.token);
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

    // --- PASSENGER INTERACTION CONNECTIONS ---
    if (role === 'guest') {
        ws.on('message', (message) => {
            try {
                const msg = JSON.parse(message);
                if (msg.type === 'guest_auth') {
                    if (dev.guestTokens.has(msg.token)) {
                        dev.guests.add(ws);
                        ws.send(JSON.stringify({ type: 'auth_ok', message: 'Connected to passenger node.' }));
                        if (dev.hudState) ws.send(JSON.stringify(dev.hudState));
                        broadcastTopology();
                        return;
                    }
                    return reject(ws, 'AUTH_FAILED', 'Passenger security vector array mismatch.');
                }
            } catch (err) {
                return reject(ws, 'PARSE_ERROR', 'Malformed data strings packet intercepted.');
            }
        });

        ws.on('close', () => {
            dev.guests.delete(ws);
            broadcastTopology();
        });
        return;
    }
});

server.listen(PORT, () => {
    console.log(`🟢 DriveOS 2.0 Centralized Hybrid Cluster Network Core Online Processing On: ${PORT}`);
});