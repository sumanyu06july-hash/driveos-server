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

// ── SPOTIFY WEB API CREDENTIALS & TOKEN CACHE ──
const SPOTIFY_CLIENT_ID = process.env.SPOTIFY_CLIENT_ID || 'ab1ac94c94a3451cbddd86b234590838';
const SPOTIFY_CLIENT_SECRET = process.env.SPOTIFY_CLIENT_SECRET || '651ff56202254b71bac158bbb2f7b3e4';

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

// ── CENTRAL VOLATILE IN-MEMORY REGISTERS ──
const devices = new Map();
const adminClients = new Set();
const blacklist = new Set();
const fingerprintBlacklist = new Set();
let globalLogSequence = 1;

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
            guestTokens: new Map(), // token -> { type, burned }
            hudState: null,
            hudLastSeen: null,
            companionState: null,
            currentTrack: null,
            hud_banned: false,
            companion_banned: false,
            parkedGuardActive: false,
            parkedCoords: null
        });
    }
    return devices.get(id);
}

app.use(express.static(path.join(__dirname)));

// ── SECURE ROUTE MIDDLEWARE: STRICT TOKEN GATING & SINGLE-USE BURNING ──
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

app.get('/guest', (req, res) => {
    const deviceId = req.query.device || 'myaura001';
    const token = req.query.token;
    const dev = devices.get(deviceId);

    if (!token || !dev || !dev.guestTokens.has(token)) {
        return res.status(403).sendFile(path.join(__dirname, 'access_denied.html')) || res.send('<h1 style="background:#080000;color:#ff2244;font-family:monospace;text-align:center;padding-top:20vh;">[SECURITY]: ACCESS DENIED — INVALID OR EXPIRED TOKEN</h1>');
    }

    const tokenMeta = dev.guestTokens.get(token);
    if (tokenMeta.burned) {
        return res.status(403).send('<h1 style="background:#080000;color:#ff2244;font-family:monospace;text-align:center;padding-top:20vh;">[SECURITY]: ACCESS DENIED — TOKEN ALREADY BURNED</h1>');
    }

    // Single-use token burn on first open
    tokenMeta.burned = true;
    dev.guestTokens.set(token, tokenMeta);
    broadcastTopology();

    res.sendFile(path.join(__dirname, 'guest.html'));
});

app.get('/summary', (req, res) => {
    const deviceId = req.query.device || 'myaura001';
    const token = req.query.token;
    const dev = devices.get(deviceId);

    if (!token || !dev || !dev.guestTokens.has(token)) {
        return res.status(403).send('<h1 style="background:#080000;color:#ff2244;font-family:monospace;text-align:center;padding-top:20vh;">[SECURITY]: ACCESS DENIED — INVALID SUMMARY TOKEN</h1>');
    }

    const tokenMeta = dev.guestTokens.get(token);
    if (tokenMeta.burned) {
        return res.status(403).send('<h1 style="background:#080000;color:#ff2244;font-family:monospace;text-align:center;padding-top:20vh;">[SECURITY]: ACCESS DENIED — SUMMARY TOKEN ALREADY BURNED</h1>');
    }

    tokenMeta.burned = true;
    dev.guestTokens.set(token, tokenMeta);
    broadcastTopology();

    res.sendFile(path.join(__dirname, 'summary.html'));
});

app.get('/player', (req, res) => res.sendFile(path.join(__dirname, 'player.html')));

app.get('/api/unban-all', (req, res) => {
    blacklist.clear();
    fingerprintBlacklist.clear();
    for (const [, dev] of devices.entries()) {
        dev.hud_banned = false;
        dev.companion_banned = false;
    }
    broadcastTopology();
    res.send('<h1 style="font-family:sans-serif;color:#00c853;">✅ SUCCESS: All device bans and fingerprint quarantines cleared from memory!</h1>');
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
                for (const [tokenKey, meta] of dev.guestTokens.entries()) {
                    tokenList.push({
                        token: tokenKey,
                        type: meta.type || 'guest',
                        burned: meta.burned || false
                    });
                }
            }

            const activeGuestsList = [];
            if (dev.guestMetadata) {
                for (const [, gMeta] of dev.guestMetadata.entries()) {
                    activeGuestsList.push(gMeta);
                }
            }

            data.push({
                id: deviceId,
                isBlacklisted: blacklist.has(deviceId),
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
        const packet = JSON.stringify({ 
            type: 'topology_update', 
            data, 
            metrics: { avgLatency },
            bannedFingerprints: Array.from(fingerprintBlacklist)
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

    // ── 🔐 ADMIN OVERLORD PIPELINE ──
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
                        
                        // Mark as burned immediately and notify connected client
                        if (tokenMeta) {
                            tokenMeta.burned = true;
                            targetDev.guestTokens.set(command.token, tokenMeta);
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
                    }
                }

                if (command.type === 'admin_unban_all_fingerprints') {
                    fingerprintBlacklist.clear();
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
                    for (const [, targetDev] of devices.entries()) {
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

    // ── 🎵 GUEST PASSENGER NEXUS (TOKEN VALIDATION REQUIRED) ──
    if (role === 'guest') {
        if (!token || !dev.guestTokens.has(token) || dev.guestTokens.get(token).burned) {
            return reject(ws, 'SECURITY_VIOLATION', 'Invalid or burned guest token.');
        }

        // Burn token on first websocket handshake as well for maximum security
        const meta = dev.guestTokens.get(token);
        meta.burned = true;
        dev.guestTokens.set(token, meta);

        dev.guests.add(ws);

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
                    dev.guestTokens.set(guestToken, { type: tokenCategory, burned: false });
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

    // ── 📊 SUMMARY CLIENT PIPELINE (TOKEN VALIDATION REQUIRED) ──
    if (role === 'summary_client') {
        if (!token || !dev.guestTokens.has(token) || dev.guestTokens.get(token).burned) {
            return reject(ws, 'SECURITY_VIOLATION', 'Invalid or burned summary token.');
        }

        const meta = dev.guestTokens.get(token);
        meta.burned = true;
        dev.guestTokens.set(token, meta);

        dev.summaryClients.set(ws, token);
        ws.send(JSON.stringify({ type: 'handshake_ok', status: 'awaiting_companion_approval' }));

        ws.on('close', () => {
            dev.summaryClients.delete(ws);
        });
        return;
    }
});

server.listen(PORT, () => console.log(`🟢 DriveOS 2.0 Centralized Hybrid Cluster Network Core Online On: ${PORT}`));