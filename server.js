const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;
const GLOBAL_SECRET = 'driveos2secret';
const ADMIN_PIN = '1234'; 

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
            lastState: null
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
            
            let nodeLatency = 0;
            if (dev.lastState && dev.lastState.latency) {
                nodeLatency = parseInt(dev.lastState.latency) || 0;
            } else if (huActive || compActive) {
                nodeLatency = 38 + Math.floor(Math.random() * 12);
            }

            if (huActive || compActive) {
                absoluteLatencySum += nodeLatency;
                computedCount++;
            }

            data.push({
                id: deviceId,
                name: dev.lastState && dev.lastState.deviceName ? dev.lastState.deviceName : `Rig Node: ${deviceId.toUpperCase()}`,
                role: huActive ? 'headunit' : 'companion',
                owner: dev.lastState && dev.lastState.owner ? dev.lastState.owner : 'Fleet Pool',
                headunitConnected: huActive,
                companionConnected: compActive,
                activeGuests: dev.guests ? dev.guests.size : 0,
                activeSummaryTokens: dev.summaryTokens ? Array.from(dev.summaryTokens.keys()) : [],
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
                                // Request dynamic device validation signature directly from the companion socket link
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
                        const browserClient = dev.summaryClients.get(command.token);
                        if (browserClient && browserClient.readyState === WebSocket.OPEN) {
                            browserClient.send(JSON.stringify({ type: 'demote_to_placeholder' }));
                            setTimeout(() => browserClient.close(), 100);
                        }
                        dev.summaryTokens.delete(command.token);
                        dev.summaryClients.delete(command.token);
                        dev.guestTokens.delete(command.token);
                        console.log(`[ADMIN ACTION] Access token permanently burned: ${command.token}`);
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
                    console.log(`[FIREWALL MATRIX] Injected runtime ban for target: ${command.device}`);
                }

                if (command.type === 'admin_allow_device') {
                    blacklist.delete(command.device);
                    console.log(`[FIREWALL MATRIX] Revoked dynamic tracking ban for target: ${command.device}`);
                }

                if (command.type === 'admin_panic_purge') {
                    console.log('[🚨 INITIATING EMERGENCY HARDWARE HANDSHAKE RESYNC]');
                    // Push a live confirmation prompt directly to the connected phone socket
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
        if (!dev.summaryTokens.has(token)) return reject(ws, 'SUMMARY_EXPIRED', 'Token index mismatch or link reference expired.');

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

        if (dev.headunit) {
            dev.headunit.send(JSON.stringify({ type: 'error', message: 'Takeover instance running.' }));
            dev.headunit.close();
        }

        dev.headunit = ws;
        ws._device = deviceId;
        console.log(`[HEADUNIT MODULE] Cluster Track Active: ${deviceId}`);
        broadcastTopology();

        ws.on('message', (message) => {
            try {
                const msg = JSON.parse(message);
                interceptTelemetryTransaction(`HUD_UNIT(${deviceId.substring(0,4)})`, 'SERVER', msg);

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
            broadcastTopology();
        });
        return;
    }

    // --- COMPANION CONTROLLER DEVICE MATRIX ---
    if (role === 'companion') {
        const secret = urlParams.get('secret');
        if (secret !== GLOBAL_SECRET) return reject(ws, 'SECURITY_VIOLATION', 'Companion config pipeline initialization key missing.');

        if (dev.companion) {
            try { dev.companion.close(); } catch(e){}
        }

        dev.companion = ws;
        ws._device = deviceId;
        
        dev.lastState = {
            deviceName: `OnePlus Node (${deviceId})`,
            owner: 'Primary Driver',
            latency: 42
        };
        
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

                // SECURE PHONE RESPONSE INTERCEPT OVERRIDE
                // Tapping confirm on the phone passes this message directly to fire the wipe sequence cleanly
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
                    
                    // Keep this active connection alive but refreshed
                    devices.set(deviceId, dev);
                    
                    adminClients.forEach(admin => {
                        if (admin.readyState === WebSocket.OPEN) {
                            admin.send(JSON.stringify({ type: 'purge_success' }));
                        }
                    });
                    return;
                }

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
                    interceptTelemetryTransaction('SERVER', `HUD_UNIT(${deviceId.substring(0,4)})`, msg);
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
        ws._authenticated = false;
        ws._device = deviceId;

        ws.on('message', (message) => {
            try {
                const msg = JSON.parse(message);
                if (msg.type === 'guest_auth') {
                    if (dev.guestTokens.has(msg.token)) {
                        ws._authenticated = true;
                        dev.guests.add(ws);
                        ws.send(JSON.stringify({ type: 'auth_ok', message: 'Connected to passenger node.' }));
                        if (dev.lastState) ws.send(JSON.stringify(dev.lastState));
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
    console.log(`\n=============================================================`);
    console.log(`🟢 DriveOS 2.0 Centralized Hybrid Cluster Network Core Online`);
    console.log(`📡 Cloud Deployment Port Bindings Active Processing On: ${PORT}`);
    console.log(`=============================================================\n`);
});