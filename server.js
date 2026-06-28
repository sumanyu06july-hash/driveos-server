// ════════════════════════════════════════
  //  HEADUNIT
  //  wss://...?role=headunit&device=myaura001&secret=driveos2secret
  //  - Only one allowed per device
  //  - Only role allowed to PUSH state
  //  - Transparent pipe for encrypted export commands → Companion
  // ════════════════════════════════════════
  if (role === 'headunit') {
    const dev = getDevice(device);

    // FIX: Instead of rejecting, terminate the old ghost connection if it exists
    if (dev.headunit && dev.headunit.readyState === WebSocket.OPEN) {
      console.log(`[CONFLICT] Ghost headunit detected for device=${device}. Terminating old connection...`);
      
      // Notify the old socket before closing it so it doesn't get stuck in a loop
      try {
        dev.headunit.send(JSON.stringify({ type: 'error', message: 'Newer connection instance took over' }));
        dev.headunit.close();
      } catch (e) {
        console.error(`Failed to cleanly close ghost headunit: ${e.message}`);
      }
    }

    // Accept the new socket immediately
    dev.headunit = ws;
    console.log(`[HEADUNIT] Connected — device: ${device}`);
    ws.send(JSON.stringify({ type: 'headunit_auth_ok', message: 'Relay active' }));

    ws.on('message', (raw) => {
      // ── TRANSPARENT PIPE ──
      if (isTransparentPipe(raw)) {
        console.log(`[PIPE] Headunit → Companion | device: ${device} | ${raw.toString().substring(0, 30)}...`);
        dev.companions.forEach(companion => {
          if (companion.readyState === WebSocket.OPEN) {
            companion.send(raw); 
          }
        });
        return;
      }

      const data = tryParse(raw);
      if (!data) return;

      // ── STATE BROADCAST ──
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
      // Safety check: Only clear it if this closed socket is actually the active one
      if (dev.headunit === ws) {
        dev.headunit = null;
        console.log(`[HEADUNIT] Disconnected — device: ${device}`);

        // Notify all connected clients
        const notice = JSON.stringify({ type: 'error', message: 'Headunit disconnected' });
        dev.companions.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(notice); });
        dev.guests.forEach(g => {     if (g.readyState === WebSocket.OPEN) g.send(notice); });
      }
    });

    ws.on('error', err => {
      console.error(`[HEADUNIT] Error — device: ${device}:`, err.message);
    });

    return;
  }