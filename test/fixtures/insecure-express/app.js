// Fixture: an Express app with auth/rate-limit/header gaps (for checker tests).
const express = require('express');
const app = express();
app.use(express.json());

// Sensitive path, no auth guard -> should be flagged by missing-auth.
app.post('/admin/delete-user', (req, res) => {
  res.send('deleted');
});

// Sensitive path, but guarded by requireAuth -> should NOT be flagged.
app.get('/admin/users', requireAuth, (req, res) => {
  res.json([]);
});

// Auth-style route, no rate limiter anywhere -> flagged by missing-rate-limit.
app.post('/login', (req, res) => {
  res.send('ok');
});

// Public, non-sensitive route -> not flagged.
app.get('/health', (req, res) => {
  res.send('ok');
});

app.listen(3000);
