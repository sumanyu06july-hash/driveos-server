const express = require('express');
const path = require('path');

const app = express();

// Serves the guest passenger page
app.get('/guest', (req, res) => {
  res.sendFile(path.join(__dirname, 'guest.html'));
});

// Health check so Render knows the server is alive
app.get('/', (req, res) => {
  res.send('DriveOS 2.0 — Relay Online');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`DriveOS server running on port ${PORT}`);
});