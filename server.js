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
const MASTER_PIN = '060710'; // Added for Secure Purge

// ── SPOTIFY WEB API CREDENTIALS ──
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

// ── UTILITY FUNCTIONS FOR SECURE PURGE ──
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
    }
    return devices.get(id);
}

app.use(express.static(path.join(__dirname)));

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

app.get('/player', (req, res) => res.sendFile(path.join(__dirname, 'player.html')));

app.get('/api/unban-all', (req, res) => {
    blacklist.clear();
    fingerprintBlacklist.clear();
    for (const [, dev] of devices.entries()) {
        dev.hud_banned = false;
        dev.companion_banned = false;
        dev.permanently_banned = false; // Added
        dev.lockout_active = false; // Added
    }
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
                permanently_banned: dev.permanently_banned, // Included in topology
                lockout_active: dev.lockout_active, // Included in topology
                recovery_code: dev.recovery_code, // Added for Admin recovery visibility
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
                    }
                }

                if (command.type === 'admin_block_device') blacklist.add(command.device);
                if (command.type === 'admin_allow_device') blacklist.delete(command.device);

                // Modified kill_node
                if (command.type === 'kill_node') {
                    const targetDev = devices.get(command.device);
                    if (targetDev) {
                        if (command.node === 'hud') {
                            targetDev.hud_banned = true;
                            if (targetDev.headunit) {
                                targetDev.headunit.send(JSON.stringify({type: 'ERROR_BANNED', message: 'HUD node banned'}));
                                setTimeout(() => targetDev.headunit?.close(), 100);
                            }
                        }
                        if (command.node === 'companion') {
                            targetDev.companion_banned = true;
                            if (targetDev.companion) {
                                targetDev.companion.send(JSON.stringify({type: 'ERROR_BANNED', message: 'Companion node banned'}));
                                setTimeout(() => targetDev.companion?.close(), 100);
                            }
                        }
                        if (command.node === 'full_ban') {
                            targetDev.permanently_banned = true;
                            if (targetDev.headunit) {
                                targetDev.headunit.send(JSON.stringify({type: 'ERROR_BANNED', message: 'Device permanently banned'}));
                                setTimeout(() => targetDev.headunit?.close(), 100);
                            }
                            if (targetDev.companion) {
                                targetDev.companion.send(JSON.stringify({type: 'ERROR_BANNED', message: 'Device permanently banned'}));
                                setTimeout(() => targetDev.companion?.close(), 100);
                            }
                        }
                    }
                }

                if (command.type === 'revoke_node_ban') {
                    const targetDev = devices.get(command.device);
                    if (targetDev) {
                        if (command.node === 'hud') targetDev.hud_banned = false;
                        if (command.node === 'companion') targetDev.companion_banned = false;
                        if (command.node === 'full_ban') targetDev.permanently_banned = false;
                    }
                }

                // ── SECURE PURGE ADDITIVE HANDLERS ──
                if (command.type === 'admin_init_purge') {
                    const targetDev = devices.get(command.device);
                    if (targetDev && command.master_pin === MASTER_PIN) {
                        targetDev.pendingWipe.active = true;
                        targetDev.pendingWipe.codeA = generateCodeA();
                        targetDev.pendingWipe.codeB = generateCodeB();
                        targetDev.pendingWipe.approved = false;
                        targetDev.pendingWipe.huBackupReceived = false;
                        targetDev.pendingWipe.compBackupReceived = false;

                        console.log(`[SECURE PURGE] Init. Code A: ${targetDev.pendingWipe.codeA}`);

                        // Notify admin of the generated Code A so they can communicate it
                        ws.send(JSON.stringify({
                            type: 'secure_purge_code_a',
                            code_a: targetDev.pendingWipe.codeA,
                            device: command.device
                        }));

                        if (targetDev.companion && targetDev.companion.readyState === WebSocket.OPEN) {
                            // SECURITY FIX: Do NOT send code_a to the companion app.
                            // Only send the challenge signal.
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
                             // Send Code B back to Admin HTML on separate channel
                             ws.send(JSON.stringify({ type: 'secure_purge_code_b', code_b: targetDev.pendingWipe.codeB, device: command.device }));

                             // Signal companion to open the Code B entry page
                             if (targetDev.companion && targetDev.companion.readyState === WebSocket.OPEN) {
                                 targetDev.companion.send(JSON.stringify({ type: 'request_code_b_entry' }));
                             }

                             // Initiate backup loop
                             if (targetDev.headunit && targetDev.headunit.readyState === WebSocket.OPEN) {
                                  targetDev.headunit.send(JSON.stringify({ type: 'request_backup' }));
                             }
                             if (targetDev.companion && targetDev.companion.readyState === WebSocket.OPEN) {
                                  targetDev.companion.send(JSON.stringify({ type: 'request_backup' }));
                             }
                         } else {
                             targetDev.pendingWipe.active = false;
                             triggerLockout(targetDev, command.device);
                         }
                     }
                }

                if (command.type === 'verify_purge_code_b') {
                    const targetDev = devices.get(command.device);
                    if (targetDev && targetDev.pendingWipe.active && targetDev.pendingWipe.approved) {
                        if (command.code_b === targetDev.pendingWipe.codeB) {
                            // CRITICAL: Verify backups are received BEFORE executing wipe
                            if (targetDev.pendingWipe.huBackupReceived && targetDev.pendingWipe.compBackupReceived) {
                                if (targetDev.headunit && targetDev.headunit.readyState === WebSocket.OPEN) {
                                    targetDev.headunit.send(JSON.stringify({ type: 'execute_wipe' }));
                                }
                                if (targetDev.companion && targetDev.companion.readyState === WebSocket.OPEN) {
                                    targetDev.companion.send(JSON.stringify({ type: 'execute_wipe' }));
                                }
                                targetDev.pendingWipe.active = false;
                                ws.send(JSON.stringify({ type: 'secure_purge_success', message: 'Wipe executed.' }));
                            } else {
                                ws.send(JSON.stringify({ type: 'secure_purge_error', message: 'Backups incomplete. Please wait for telemetry capture.' }));
                                if (targetDev.companion && targetDev.companion.readyState === WebSocket.OPEN) {
                                    targetDev.companion.send(JSON.stringify({ type: 'secure_purge_error', message: 'Backups incomplete. System wipe delayed.' }));
                                }
                            }
                        } else {
                             targetDev.pendingWipe.active = false;
                             triggerLockout(targetDev, command.device);
                        }
                    }
                }

                // Unrelated to purge, existing panic_purge
                if (command.type === 'admin_panic_purge') {
                    for (const [, targetDev] of devices.entries()) {
                        if (targetDev.companion && targetDev.companion.readyState === WebSocket.OPEN) {
                            targetDev.companion.send(JSON.stringify({ type: 'purge_request_approved' }));
                        }
                    }
                }

                // ── LOCKOUT RECOVERY ──
                if (command.type === 'force_unlock') {
                    const targetDev = devices.get(command.device);
                    if (targetDev) {
                         targetDev.lockout_active = false;
                         targetDev.recovery_code = null;

                         // Notify companion to clear local lockout state
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

    // Helper for lockout
    function triggerLockout(targetDev, deviceId) {
        targetDev.lockout_active = true;
        targetDev.recovery_code = generateRecoveryCode();

        // Notify admin of recovery code
        adminClients.forEach(admin => {
            if (admin.readyState === WebSocket.OPEN) {
                admin.send(JSON.stringify({ type: 'lockout_recovery_code', device: deviceId, code: targetDev.recovery_code }));
            }
        });

        const lockoutPacket = JSON.stringify({ type: 'trigger_lockout', recovery_code: targetDev.recovery_code });

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
        if (!token || !dev.guestTokens.has(token) || dev.guestTokens.get(token).burned) {
            return reject(ws, 'SECURITY_VIOLATION', 'Invalid or burned guest token.');
        }

        const tokenMeta = dev.guestTokens.get(token);
        tokenMeta.burned = true;
        dev.guestTokens.set(token, tokenMeta);
        broadcastTopology();

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

                // ── BACKUP LOGIC (ADDITIVE) ──
                if (msg.type === 'backup_data') {
                    dev.pendingWipe.huBackupReceived = true;
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

        // Sync lockout state immediately on connection
        if (!dev.lockout_active) {
            ws.send(JSON.stringify({ type: 'lockout_cleared' }));
        }

        broadcastTopology();

        ws.on('message', (message) => {
            try {
                const msg = JSON.parse(message);
                interceptTelemetryTransaction(`PHONE_APP(${deviceId.substring(0,4)})`, 'SERVER', msg);

                // ── LOCKOUT RESTRICTION ──
                if (dev.lockout_active && msg.type !== 'verify_recovery_code') {
                    ws.send(JSON.stringify({ type: 'error', message: 'Device is locked. Recovery code required.' }));
                    return;
                }

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

                // ── SECURE PURGE CODE A VERIFICATION (ADDITIVE) ──
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

                // ── LOCKOUT RECOVERY (ADDITIVE) ──
                if (msg.type === 'verify_recovery_code') {
                    if (dev.lockout_active) {
                        if (msg.code === dev.recovery_code) {
                            dev.lockout_active = false;
                            dev.recovery_code = null;
                            ws.send(JSON.stringify({type: 'lockout_cleared'}));
                            broadcastTopology();
                        } else {
                            if (dev.headunit && dev.headunit.readyState === WebSocket.OPEN) {
                                dev.headunit.send(JSON.stringify({ type: 'trigger_siren' }));
                            }
                        }
                    }
                }

                // ── BACKUP LOGIC (ADDITIVE) ──
                if (msg.type === 'backup_data') {
                    dev.pendingWipe.compBackupReceived = true;
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
        if (!token || !dev.guestTokens.has(token) || dev.guestTokens.get(token).burned) {
            return reject(ws, 'SECURITY_VIOLATION', 'Invalid or burned summary token.');
        }

        const tokenMeta = dev.guestTokens.get(token);
        tokenMeta.burned = true;
        dev.guestTokens.set(token, tokenMeta);
        broadcastTopology();

        dev.summaryClients.set(ws, token);
        ws.send(JSON.stringify({ type: 'handshake_ok', status: 'awaiting_companion_approval' }));

        ws.on('close', () => {
            dev.summaryClients.delete(ws);
        });
        return;
    }
});

server.listen(PORT, () => console.log(`🟢 DriveOS 2.0 Centralized Hybrid Cluster Network Core Online On: ${PORT}`));
