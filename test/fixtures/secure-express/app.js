// Fixture: an Express app that is properly hardened (checker true-negatives).
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(helmet());
app.use(express.json());

const authLimiter = rateLimit({ windowMs: 60000, max: 10 });

app.post('/login', authLimiter, requireAuth, (req, res) => {
  res.send('ok');
});

app.get('/admin/users', requireAuth, (req, res) => {
  res.json([]);
});

app.listen(3000);
